# Atlassian JWT Authentication

Atlassian JWT Authentication provides support for handling JWT authentication as required by
 Atlassian when building add-ons: https://developer.atlassian.com/static/connect/docs/latest/concepts/authentication.html

## Installation

### From Git

You can check out the latest source from git:

`git clone https://github.com/MeisterLabs/atlassian-jwt-authentication.git`

Or, if you're using Bundler, just add the following to your Gemfile:

```ruby
gem 'atlassian-jwt-authentication', 
  git: 'https://github.com/MeisterLabs/atlassian-jwt-authentication.git'
```

## Usage

### Setup

This gem relies on the `jwt_tokens` and `jwt_users` tables being present in your database and 
the associated JwtToken and JwtUser models.

To create those simply use the provided generators:

```
bundle exec rails g atlassian_jwt_authentication:setup
```

If you are using another database for the JWT data storage than the default one, pass the name of the DB config to the generator:
```
bundle exec rails g atlassian_jwt_authentication:setup shared
```

Don't forget to run your migrations now!

### Controller filters

The gem provides 2 endpoints for an Atlassian add-on lifecycle, installed and uninstalled. 
For more information on the available Atlassian lifecycle callbacks visit 
https://developer.atlassian.com/static/connect/docs/latest/modules/lifecycle.html.

If your add-on baseUrl is not your application root URL then include the following 
configuration for the context path. This is needed in the query hash string validation 
step of verifying the JWT:
```ruby
# In the add-on descriptor:
# "baseUrl": "https://www.example.com/atlassian/confluence",

AtlassianJwtAuthentication.context_path = '/atlassian/confluence'
```

#### Add-on installation
The gem will take care of setting up the necessary JWT tokens upon add-on installation and to
delete the appropriate tokens upon un-installation. To use this functionality, simply call
 
```ruby
include AtlassianJwtAuthentication

before_action :on_add_on_installed, only: [:installed]
before_action :on_add_on_uninstalled, only: [:uninstalled]
```

#### Add-on authentication
Furthermore, protect the methods that will be JWT aware by using the gem's
JWT token verification filter. You need to pass your add-on descriptor so that
the appropriate JWT shared secret can be identified:

```ruby
include AtlassianJwtAuthentication

# will respond with head(:unauthorized) if verification fails
before_filter only: [:display, :editor] do |controller|
  controller.send(:verify_jwt, 'your-add-on-key')
end
```

Methods that are protected by the `verify_jwt` filter also have access to information
about the current JWT authentication instance and the JWT user (when available).
Furthermore, this information is stored in the session so you will have access
to these 2 instances also on subsequent requests even if they are not JWT signed.

```ruby
# current_jwt_auth returns an instance of JwtToken, so you have access to the fields described above
pp current_jwt_auth.addon_key

# current_jwt_user is an instance of JwtUser, so you have access to the Atlassian user information.
# Beware, this information is not present when developing for Bitbucket.
pp current_jwt_user.user_key
pp current_jwt_user.name
pp current_jwt_user.display_name
```

#### Add-on licensing
If your add-on has a licensing model you can use the `ensure_license` filter to check for a valid license.
As with the `verify_jwt` filter, this simply responds with an unauthorized header if there is no valid license
for the installation.

```ruby
before_filter :ensure_license
```
If your add-on was for free and you're just adding licensing now, you can specify
the version at which you started charging, ie. the minimum version of the add-on
for which you require a valid license. Simply include the code below with your version
string in the controller that includes the other add-on code.
```ruby
def min_licensing_version
  Gem::Version.new('1.0.0')
end
```

### Middleware

You can use a middleware to verify JWT tokens (for example in Rails `application.rb`):

```ruby
config.middleware.insert_after ActionDispatch::Session::CookieStore, AtlassianJwtAuthentication::Middleware::VerifyJwtToken, 'your_addon_key'
```

Token will be taken from params or `Authorization` header, if it's verified successfully request will have following headers set:

* atlassian_jwt_authorization.jwt_token `JwtToken` instance
* atlassian_jwt_authorization.jwt_user `JwtUser` instance
* atlassian_jwt_authorization.client_token refreshed JWT token for callbacks

Middleware will not block requests with invalid or missing JWT tokens, you need to use another layer for that.

### Making a service call

Build the URL required to make a service call with the `rest_api_url` helper or
make a service call with the `rest_api_call` helper that will handle the request for you.
Both require the method and the endpoint that you need to access:

```ruby
# Get available project types
url = rest_api_url(:get, '/rest/api/2/project/type')
response = HTTParty.get(url)

# Create an issue
data = {
    fields: {
        project: {
            'id': 10100
        },
        summary: 'This is an issue summary',
        issuetype: {
            id: 10200
        }
    }
}

response = rest_api_call(:post, '/rest/api/2/issue', data)
pp response.success?

```


### Preparing service gateways

You can also prepare a service gateway that will encapsulate communication methods with the product. Here's a sample JIRA gateway:

```ruby
class JiraGateway

  class << self
    def new(current_jwt_auth, user_key = nil)
      Class.new(AbstractJiraGateway) do |klass|
        klass.base_uri(
          current_jwt_auth.respond_to?(:api_base_url) ?
            current_jwt_auth.api_base_url :
            current_jwt_auth.base_url)
      end.new(current_jwt_auth, user_key)
    end
  end

  class AbstractJiraGateway
    include HTTParty
    include AtlassianJwtAuthentication::HTTParty

    def initialize(current_jwt_auth, user_key = nil)
      @current_jwt_auth = current_jwt_auth
      @user_key = user_key
    end

    def user(user_key)
      self.class.get_with_jwt('/rest/api/2/user', {
        query: {
          key: user_key
        },
        current_jwt_auth: @current_jwt_auth,
        user_key: @user_key,
      })
    end
  end
end
```

Then use it in your controller:

```ruby
JiraGateway.new(current_jwt_auth).user('admin')
```

### User impersonification

To make requests on user's behalf use `act_as_user` in scopes then obtain [OAuth bearer token](https://developer.atlassian.com/cloud/jira/software/oauth-2-jwt-bearer-token-authorization-grant-type/) from Atlassian.

You can do that easily using `JiraGateway` presented above, just pass `user_key` of the user you want to act on behalf of:

```ruby
JiraGateway.new(current_jwt_auth, 'user_key').add_worklog(issue.key, '1m')
``` 

`AtlassianJwtAuthentication::HTTParty` will detect presence of `user_key` and obtain OAuth token automatically, tokens are cached using `Rails.cache`, check `lib/atlassian-jwt-authentication/user_bearer_token.rb` 

## Installing the add-on

You can use rake tasks to simplify plugin installation:

```ruby
bin/rails atlassian:install[prefix,username,password,https://external.address.to/descriptor]
```

Where `prefix` is your instance name before `.atlassian.net`.

## Requirements

Ruby 2.0+, ActiveRecord 4.1+

## Integrations

### Message Bus

In `application.rb` register our middleware:

```ruby
config.middleware.insert_after ActionDispatch::Session::CookieStore, AtlassianJwtAuthentication::Middleware::VerifyJwtToken, 'plugin_key'
```

With middleware enabled you can use following configuration to limit access to message bus per user / instance:
```ruby
MessageBus.user_id_lookup do |env|
  # We switched to user_key because they are available in all web requests from connect, user_id is sth you need to take from Jira via api
  env.try(:[], 'atlassian_jwt_authentication.jwt_user').try(:user_key)
end

MessageBus.site_id_lookup do |env|
  env.try(:[], 'atlassian_jwt_authentication.jwt_token').try(:id)
end

MessageBus.extra_response_headers_lookup do |env|
  {}.tap do |headers|
    if env['atlassian_jwt_authentication.client_token']
      headers['x-acpt'] = env['atlassian_jwt_authentication.client_token']
    end
  end
end
```

Then use `MessageBus.publish('/test', 'message', site_id: X, user_ids: [Y])` to publish message only for a user.

Requires message_bus patch available at https://github.com/HeroCoders/message_bus/commit/cd7c752fe85a17f7e54aa950a94d7c6378a55ed1