module Authorization
  module AuthorizableByDefault
    def self.included(base)
      base.class_eval do
        acts_as_authorizable
        alias :authorized_users :users
      end
    end
  end
end
