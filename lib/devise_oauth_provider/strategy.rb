require 'devise/strategies/base'

module Devise
  module OAuthProvider

    module Strategies
      # Default strategy for signing in a user, based on his email and password.
      # Redirects to sign_in page if it's not authenticated
      class OAuthProvider < Devise::Strategies::Base

        def valid?
          request.headers["HTTP_AUTHORIZATION"] =~ /^OAuth/
        end

        def authenticate!      
          valid = if params[:action] == 'request_token'
            if verify_oauth_consumer_signature
              #success!(@current_client_application.account)
              success!(Account.find_by_username("BlocksApp"))
            else
              fail!(:invalid)
            end
          elsif params[:action] == 'access_token'
            #success!(@current_client_application.account) if verify_oauth_request_token
            success!(Account.find_by_username("BlocksApp")) if verify_oauth_request_token
          else
            succ = verify_oauth_signature
            if succ && @current_token.is_a?(::AccessToken) && !!@current_token.account
              success!(@current_token.account)
            else
              fail!(:invalid)
            end
          end
          fail!(:invalid)
        end
        
        
        # verifies a request token request
        def verify_oauth_consumer_signature
          ClientApplication.verify_request(request) do |request_proxy|
            self.current_client_application = ClientApplication.find_by_key(request_proxy.consumer_key)
            # Store this temporarily in client_application object for use in request token generation 
            @current_client_application.token_callback_url=request_proxy.oauth_callback if request_proxy.oauth_callback
            # return the token secret and the consumer secret
            [nil, @current_client_application.secret]
          end
        rescue => e
          ActiveRecord::Base.logger.warn e.inspect
          false
        end

        def verify_oauth_request_token
          verify_oauth_signature && current_token.is_a?(::RequestToken)
        end

        # def invalid_oauth_response(code=401,message="Invalid OAuth Request")
        #           puts "get out of here"
        #           render(:text => message, :status => code) and return
        #         end

        def current_token
          @current_token
        end

        def current_client_application
          @current_client_application
        end
        
        def current_client_application=(app)
          @current_client_application = app
          session['current_client_application'] = app.id
        end


        private #############################

        def current_token=(token)
          @current_token = token
          session['current_token'] = token.id
          if @current_token
            #@current_user=@current_token.account
            self.current_client_application = @current_token.client_application 
          end
          @current_token
        end
        
        
        def verify_oauth_signature
          ClientApplication.verify_request(request) do |request_proxy|
            self.current_token = ClientApplication.find_token(request_proxy.token)
            
            if self.current_token.respond_to?(:provided_oauth_verifier=)
              self.current_token.provided_oauth_verifier = request_proxy.oauth_verifier 
            end
            
            # return the token secret and the consumer secret
            [(current_token.nil? ? nil : current_token.secret), (self.current_client_application.nil? ? nil : self.current_client_application.secret)]
          end
        rescue
          false
        end
        
      end
    end
  end
end
Warden::Strategies.add(:oauth_provider, Devise::OAuthProvider::Strategies::OAuthProvider)