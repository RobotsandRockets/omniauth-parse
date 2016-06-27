require 'omniauth'
require 'faraday'

module OmniAuth
  module Strategies
    class Parse
      include OmniAuth::Strategy

      option :fields, [:username, :password]
      option :uid_field, :username

      def request_phase
        form = OmniAuth::Form.new(:title => "Parse.com Info", :url => callback_path)
          form.text_field :username, :username
          form.password_field :password, :password
        form.button "Sign In"
        form.to_response
      end

      def callback_phase
        @raw_data = get_user_data
        return fail!(:invalid_credentials) unless @raw_data
        @parsed_data = JSON.parse @raw_data
        super
      end

      uid { @parsed_data.delete "objectId"  }

      info do
        @parsed_data
      end

      def get_user_data

        raise "application_id is required for initialization" unless options[:application_id]
        raise "rest_api_key is required for initialization"   unless options[:rest_api_key]

        options[:api_url] ||= "https://api.parse.com/1"

        conn = Faraday.new(:url => options[:api_url]) do |req|
          req.request :url_encoded
          req.adapter  Faraday.default_adapter
        end
        result = conn.get do |req|
          req.url "login"
          req.headers['X-Parse-Application-Id'] = options[:application_id]
          req.headers['X-Parse-REST-API-Key']   = options[:rest_api_key]
          req.params['username']                = request.params["username"]
          req.params['password']                = request.params["password"]
        end
        unless result.status == 200
          #logging?
          return false
        end
        return result.body
      end
    end
  end
end
