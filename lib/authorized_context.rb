module Authorization
  module AuthorizedContext

    if not Object.constants.include? "SUPERUSER_ROLE"
      SUPERUSER_ROLE = nil
    end

    def self.included(base)
      base.extend ClassMethods
      base.send(:include, InstanceMethods)
    end

    class AuthorizedContextError < StandardError; end
    class NoRulesFoundForContext < AuthorizedContextError; end
    class NoRulesFoundForController < AuthorizedContextError; end
    class AccessDenied < AuthorizedContextError; end
    class NoRoleForPermissions < AuthorizedContextError; end
    class BadTypeProvidedForPermission < AuthorizedContextError; end
    class BadTypeProvidedForRole < AuthorizedContextError; end
    class AccessDenied < AuthorizedContextError; end
    class LoginRequired < AuthorizedContextError; end

    class Permissions

      def initialize(controller)
        @controller = controller
        @permissions = {}
      end

      def [](permission)
        @permissions[permission]
      end

      def []=(permission)
        @permissions[permission]
      end

      def grant(who)
        raise BadTypeProvidedForRole unless who.is_a?(String)
        @actual_role = who
      end

      def can(*perms)
        raise NoRoleForPermissions unless @actual_role
  
        perms.each do |p|
          case p
          when String
            @permissions[p] = @actual_role
          when Hash
            p.each do |context, actions|
              @permissions[context] = @actual_role
              actions = [actions] unless actions.is_a? Array
              actions.each do |action|
                @controller.class_eval do
                  before_filter :only =>actions do |controller|
                    debugger
                    controller.authorized_context(context)
                  end
                end
              end
            end
          else
            raise BadTypeProvidedForPermission
          end
        end
      end

    end
    
    module ClassMethods
      
      def grant(*args, &block)
        if block_given?
          @@permission_rules = Permissions.new(self)
          @@permission_rules.instance_eval(&block)
        end
        unless args.empty?
          permit(*args)
        end
      end
      
      def permission_rules
        @@permission_rules
      end

    end

    module InstanceMethods

      def authorized_context(name, *args, &blk)
        @options = { :permission_denied_message => PERMISSION_DENIED_MESSAGE, :login_required_message => LOGIN_REQUIRED_MESSAGE }
        @options.merge!( args.last.is_a?( Hash ) ? args.last : {} )
        permit_context(name, @options, &blk)
      end

      def authorized_to?(name, *args)
        return true if AUTHORIZATION_SUPERUSER_ROLE && current_user.has_role?(AUTHORIZATION_SUPERUSER_ROLE)
        check_permission_rules_for_controller
        @options = { :allow_guests => false, :redirect => true }
        @options.merge!( args.last.is_a?( Hash ) ? args.last : {} )
        check_permission_rules_for_context(name)
        authorization_expression = permission_rules[name]
        permit? authorization_expression, *args
      end

      def permission_rules
        if defined? controller 
          controller.permission_rules
        else
          self.class.permission_rules
        end
      end

      # Added on_access_denied and on_login_required event handlers calls
      def permit( authorization_expression, *args )
        @options = { :allow_guests => false, :redirect => true }
        @options.merge!( args.last.is_a?( Hash ) ? args.last : {} )
        if has_permission?( authorization_expression) || (SUPERUSER_ROLE && @current_user.has_role?(SUPERUSER_ROLE))
          yield if block_given?
        elsif @current_user && @current_user != :false && self.respond_to?(:on_access_denied)
          self.send(:on_access_denied, @actual_authorized_context) and return false
        elsif (!@current_user || @current_user == :false) && self.respond_to?(:on_login_required)
          self.send(:on_login_required, @actual_authorized_context) and return false
        elsif @options[:redirect]
          handle_redirection
        end
      end

      private

      def permit_context(name, *args, &blk)
        check_permission_rules_for_controller
        check_permission_rules_for_context(name)
        @actual_authorized_context = name
        authorization_expression = permission_rules[name]
        permit(authorization_expression, *args, &blk)
      end

      def check_permission_rules_for_controller
        unless defined? permission_rules
        then raise( NoRulesFoundForController, "No permission rules found for controller \"#{controller_name}\". Set the permissions first!") end
      end
  
      def check_permission_rules_for_context(context_name)
        if permission_rules[context_name].blank?
        then raise( NoRulesFoundForContext, "\"#{context_name}\" -- No permission rules found for this context. Please, check the name of the context or set the permissions rules.") end
      end

    end
  end
end
