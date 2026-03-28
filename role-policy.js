const ROLE_NAMES = Object.freeze({
  ADMIN: "Admin",
  PERSONAL_ACCOUNT: "Personal Account",
  EDITOR: "Editor",
  VIEWER: "Viewer",
  MEMBER: "Member",
  TEAM_LEADER: "Team Leader"
});

const PERMISSIONS = Object.freeze({
  VIEW_TASKS: "view_tasks",
  WRITE_TASKS: "write_tasks",
  MANAGE_USERS_ROLES: "manage_users_roles",
  MANAGE_TEAMS: "manage_teams",
  MANAGE_OWN_TEAM: "manage_own_team"
});

const ACCESS_POLICY = Object.freeze({
  [ROLE_NAMES.ADMIN]: Object.freeze([
    PERMISSIONS.VIEW_TASKS,
    PERMISSIONS.WRITE_TASKS,
    PERMISSIONS.MANAGE_USERS_ROLES
  ]),
  [ROLE_NAMES.EDITOR]: Object.freeze([
    PERMISSIONS.VIEW_TASKS,
    PERMISSIONS.WRITE_TASKS
  ]),
  [ROLE_NAMES.TEAM_LEADER]: Object.freeze([
    PERMISSIONS.VIEW_TASKS,
    PERMISSIONS.WRITE_TASKS,
    PERMISSIONS.MANAGE_OWN_TEAM
  ]),
  [ROLE_NAMES.PERSONAL_ACCOUNT]: Object.freeze([
    PERMISSIONS.VIEW_TASKS
  ]),
  [ROLE_NAMES.MEMBER]: Object.freeze([
    PERMISSIONS.VIEW_TASKS
  ]),
  [ROLE_NAMES.VIEWER]: Object.freeze([
    PERMISSIONS.VIEW_TASKS
  ])
});

function can(roleName, permission) {
  if (!roleName || !permission) return false;
  return ACCESS_POLICY[roleName]?.includes(permission) || false;
}

function buildPermissions(roleName) {
  return {
    canViewTasks: can(roleName, PERMISSIONS.VIEW_TASKS),
    canWriteTasks: can(roleName, PERMISSIONS.WRITE_TASKS),
    canManageUsersRoles: can(roleName, PERMISSIONS.MANAGE_USERS_ROLES),
    canManageTeams: can(roleName, PERMISSIONS.MANAGE_TEAMS),
    canManageOwnTeam: can(roleName, PERMISSIONS.MANAGE_OWN_TEAM)
  };
}

module.exports = {
  ROLE_NAMES,
  PERMISSIONS,
  ACCESS_POLICY,
  can,
  buildPermissions
};
