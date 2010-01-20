require File.dirname(__FILE__) + '/lib/authorization'
require File.dirname(__FILE__) + '/lib/authorized_context'
require File.dirname(__FILE__) + '/lib/computed_roles'
require File.dirname(__FILE__) + '/lib/authorizable_by_default'

ActionController::Base.send( :include, Authorization::Base )
ActionView::Base.send( :include, Authorization::Base::ControllerInstanceMethods )

ActionController::Base.send(:include, Authorization::AuthorizedContext)
ActionView::Base.send(:include, Authorization::AuthorizedContext::InstanceMethods)

# You can perform authorization at varying degrees of complexity.
# Choose a style of authorization below (see README.txt) and the appropriate
# mixin will be used for your app.

# When used with the auth_test app, we define this in config/environment.rb
# AUTHORIZATION_MIXIN = "hardwired"
if not Object.constants.include? "AUTHORIZATION_MIXIN"
  if  not (Object.constants.include?("USE_ROLES_TABLE") && !USE_ROLES_TABLE) 
    AUTHORIZATION_MIXIN = "object roles"
  else
    AUTHORIZATION_MIXIN = "hardwired"
  end
end

if not Object.constants.include? "AUTHORIZABLE_BY_DEFAULT"
  AUTHORIZABLE_BY_DEFAULT = true
end

case AUTHORIZATION_MIXIN
  when "hardwired"
    require File.dirname(__FILE__) + '/lib/publishare/hardwired_roles'
    ActiveRecord::Base.send( :include, 
      Authorization::HardwiredRoles::UserExtensions, 
      Authorization::HardwiredRoles::ModelExtensions 
    )
  when "object roles"
    require File.dirname(__FILE__) + '/lib/publishare/object_roles_table'
    ActiveRecord::Base.send( :include, 
      Authorization::ObjectRolesTable::UserExtensions, 
      Authorization::ObjectRolesTable::ModelExtensions
    )
end

ActiveRecord::Base.send(:include, Authorization::Base::ComputedRoles)

if AUTHORIZABLE_BY_DEFAULT
  ActiveRecord::Base.send(:include, Authorization::AuthorizableByDefault)
end


