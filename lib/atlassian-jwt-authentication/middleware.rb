module AtlassianJwtAuthentication
  module Middleware
    class VerifyJwtToken
      PREFIX = 'atlassian_jwt_authentication'.freeze

      JWT_TOKEN_HEADER = "#{PREFIX}.jwt_token".freeze
      JWT_USER_HEADER = "#{PREFIX}.jwt_user".freeze
      CLIENT_TOKEN_HEADER = "#{PREFIX}.client_token".freeze

      def initialize(app, addon_key)
        @app = app
        @addon_key = addon_key
      end

      def call(env)
        request = ActionDispatch::Request.new(env)

        jwt = request.params[:jwt]

        if request.headers['authorization'].present?
          algorithm, possible_jwt = request.headers['authorization'].split(' ')
          jwt = possible_jwt if algorithm == 'JWT'
        end

        if jwt
          jwt_auth, jwt_user, client_token = Verify.verify_jwt(@addon_key, jwt, request, [])

          if jwt_auth
            request.set_header(JWT_TOKEN_HEADER, jwt_auth)
          end

          if jwt_user
            request.set_header(JWT_USER_HEADER, jwt_user)
          end

          if client_token
            request.set_header(CLIENT_TOKEN_HEADER, client_token)
          end
        end

        status, headers, body = @app.call(env)

        Rack::Response.new(body, status, headers).tap do |response|
          response.set_header('x-acpt', client_token) if client_token
        end.finish
      end
    end
  end
end