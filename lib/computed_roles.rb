module Authorization
  module Base
    module ComputedRoles

      def self.included(base)
        base.extend ClassMethods
      end

      class AuthorizationExpressionInvalid < StandardError; end;

      module ClassMethods

        def acts_as_authorized_user(roles_relationship_opts = {})
          super
          class_inheritable_hash :computed_roles, :computed_relationships
          self.computed_relationships = {}
          self.computed_roles = {}
          include Authorization::Base::ComputedRoles::InstanceMethods
        end

        def has_role(str, opts={})
          if str =~ /[^A-Za-z0-9_:'\(\)\s]/
            raise AuthorizationExpressionInvalid, "Invalid authorization expression (#{str})"
            return false
          end
          role_regex = '\s*(\'\s*(.+?)\s*\'|(\w+))\s+'
          just_role_regex = /\s*(\'\s*(.+?)\s*\'|(\w+))\s*/
          model_regex = '\s+(:*\w+)'
          relationship_regex = Regexp.new(role_regex + '(' + VALID_PREPOSITIONS.join('|') + ')' + model_regex)
          (str =~ relationship_regex) || (str =~ just_role_regex)
          role   = $1 || $2
          model  = $5
          cond   = opts[:if]
          if model
            computed_relationships[model] ||= {}
            computed_relationships[model][role] = cond
          else
            computed_roles[role] = cond
          end
        end

      end

      module InstanceMethods

        def has_role?(role, auth_object=nil)
          rels = computed_relationships
          rols = computed_roles
          model = auth_object.class.to_s.underscore if auth_object
          if model && rels.has_key?(model) && rels[model].has_key?(role)
            rels[model][role].call(self, auth_object)
          elsif rols.has_key?(role)
            rols[role].call(self)
          else
            super
          end
        end
        
        def computed_relationships
          self.class.computed_relationships
        end

        def computed_roles
          self.class.computed_roles
        end

      end

    end
  end
end
