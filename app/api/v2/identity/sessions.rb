# frozen_string_literal: true

require_dependency 'barong/jwt'
require 'net/http'
require 'faraday'
require 'uri'

module API::V2
  module Identity
    class Sessions < Grape::API
      helpers do
        def get_user(email)
          user = User.find_by(email: email)
          error!({ errors: ['identity.session.invalid_params'] }, 401) unless user

          if user.state == 'banned'
            login_error!(reason: 'Your account is banned', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'banned')
          end

          if user.state == 'deleted'
            login_error!(reason: 'Your account is deleted', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'deleted')
          end

          # if user is not active or pending, then return 401
          unless user.state.in?(%w[active pending])
            login_error!(reason: 'Your account is not active', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'not_active')
          end
          user
        end
      end
      desc 'Session related routes'
      resource :sessions do
        desc 'Start a new session',
             failure: [
               { code: 400, message: 'Required params are empty' },
               { code: 404, message: 'Record is not found' }
             ]
        params do
          requires :email
          requires :password
          optional :captcha_response,
                   types: { value: [String, Hash], message: 'identity.session.invalid_captcha_format' },
                   desc: 'Response from captcha widget'
          optional :otp_code,
                   type: String,
                   desc: 'Code from Google Authenticator'
        end
        post do
          verify_captcha!(response: params['captcha_response'], endpoint: 'session_create')

          declared_params = declared(params, include_missing: false)
          user = get_user(declared_params[:email])

          unless user.authenticate(declared_params[:password])
            login_error!(reason: 'Invalid Email or Password', error_code: 401, user: user.id,
                         action: 'login', result: 'failed', error_text: 'invalid_params')
          end

          unless user.otp
            activity_record(user: user.id, action: 'login', result: 'succeed', topic: 'session')
            csrf_token = open_session(user)
            publish_session_create(user)

            present user, with: API::V2::Entities::UserWithFullInfo, csrf_token: csrf_token
            return status 200
          end

          error!({ errors: ['identity.session.missing_otp'] }, 401) if declared_params[:otp_code].blank?
          unless TOTPService.validate?(user.uid, declared_params[:otp_code])
            login_error!(reason: 'OTP code is invalid', error_code: 403,
                         user: user.id, action: 'login::2fa', result: 'failed', error_text: 'invalid_otp')
          end

          activity_record(user: user.id, action: 'login::2fa', result: 'succeed', topic: 'session')
          csrf_token = open_session(user)
          publish_session_create(user)

          present user, with: API::V2::Entities::UserWithFullInfo, csrf_token: csrf_token
          status(200)
        end

        desc 'Destroy current session',
             failure: [
               { code: 400, message: 'Required params are empty' },
               { code: 404, message: 'Record is not found' }
             ]
        delete do
          user = User.find_by(uid: session[:uid])
          error!({ errors: ['identity.session.not_found'] }, 404) unless user

          activity_record(user: user.id, action: 'logout', result: 'succeed', topic: 'session')

          session.destroy
          status(200)
        end

        namespace :auth0 do
          desc 'Auth0 authentication',
               success: { code: 200, message: '' },
               failure: [
                 { code: 400, message: 'Required params are empty' },
                 { code: 404, message: 'Record is not found' }
               ]

          get '/authorize' do
            uri = URI::HTTPS.build(host: Barong::App.config.auth0_tenant_address, path: '/authorize', query: {
              response_type: 'code',
              client_id: Barong::App.config.client_id,
              redirect_uri: Barong::App.config.redirect_uri,
              scope: 'openid profile email',
              audience: Barong::App.config.audience
            }.to_query)
            redirect uri
          end

          params do
            requires :code
          end
          get '/auth' do
            url = "https://#{Barong::App.config.auth0_tenant_address}/oauth/token"
            data = {
              grant_type: 'authorization_code',
              client_id: Barong::App.config.client_id,
              client_secret: Barong::App.config.client_secret,
              code: params[:code],
              redirect_uri: Barong::App.config.redirect_uri
            }
            response = Faraday.post(url) do |req|
              req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
              req.body = URI.encode_www_form(data)
            end
            if response.status == 200
              json = JSON.parse(response.body)
              id_token = json['id_token']

              claims = JWT.decode(id_token, nil, false, algorithm: 'RS256')
              user = get_user(claims[0]['email'])

              activity_record(user: user.id, action: 'login::2fa', result: 'succeed', topic: 'session')
              csrf_token = open_session(user)
              publish_session_create(user)

              present user, with: API::V2::Entities::UserWithFullInfo, csrf_token: csrf_token
              status(200)
            end
            status(response.status)
          end
        end
      end
    end
  end
end
