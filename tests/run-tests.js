const assert = require("node:assert/strict");
const { ROLE_NAMES, PERMISSIONS, can, buildPermissions } = require("../role-policy");

function runTest(name, fn) {
  try {
    fn();
    console.log(`PASS: ${name}`);
  } catch (error) {
    console.error(`FAIL: ${name}`);
    console.error(error.message);
    process.exitCode = 1;
  }
}

runTest("Admin is developer-only and manages users/roles", () => {
  assert.equal(can(ROLE_NAMES.ADMIN, PERMISSIONS.VIEW_TASKS), false);
  assert.equal(can(ROLE_NAMES.ADMIN, PERMISSIONS.WRITE_TASKS), false);
  assert.equal(can(ROLE_NAMES.ADMIN, PERMISSIONS.MANAGE_USERS_ROLES), true);
  assert.equal(can(ROLE_NAMES.ADMIN, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Editor can read/write tasks but cannot manage users/roles", () => {
  assert.equal(can(ROLE_NAMES.EDITOR, PERMISSIONS.VIEW_TASKS), true);
  assert.equal(can(ROLE_NAMES.EDITOR, PERMISSIONS.WRITE_TASKS), true);
  assert.equal(can(ROLE_NAMES.EDITOR, PERMISSIONS.MANAGE_USERS_ROLES), false);
  assert.equal(can(ROLE_NAMES.EDITOR, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Viewer can read tasks only and cannot manage privileged areas", () => {
  assert.equal(can(ROLE_NAMES.VIEWER, PERMISSIONS.VIEW_TASKS), true);
  assert.equal(can(ROLE_NAMES.VIEWER, PERMISSIONS.WRITE_TASKS), false);
  assert.equal(can(ROLE_NAMES.VIEWER, PERMISSIONS.MANAGE_USERS_ROLES), false);
  assert.equal(can(ROLE_NAMES.VIEWER, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Team Leader can read/write tasks but cannot manage admin controls", () => {
  assert.equal(can(ROLE_NAMES.TEAM_LEADER, PERMISSIONS.VIEW_TASKS), true);
  assert.equal(can(ROLE_NAMES.TEAM_LEADER, PERMISSIONS.WRITE_TASKS), true);
  assert.equal(can(ROLE_NAMES.TEAM_LEADER, PERMISSIONS.MANAGE_USERS_ROLES), false);
  assert.equal(can(ROLE_NAMES.TEAM_LEADER, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Personal Account can read tasks only and cannot manage privileged areas", () => {
  assert.equal(can(ROLE_NAMES.PERSONAL_ACCOUNT, PERMISSIONS.VIEW_TASKS), true);
  assert.equal(can(ROLE_NAMES.PERSONAL_ACCOUNT, PERMISSIONS.WRITE_TASKS), false);
  assert.equal(can(ROLE_NAMES.PERSONAL_ACCOUNT, PERMISSIONS.MANAGE_USERS_ROLES), false);
  assert.equal(can(ROLE_NAMES.PERSONAL_ACCOUNT, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Member can read tasks but cannot write or manage admin controls", () => {
  assert.equal(can(ROLE_NAMES.MEMBER, PERMISSIONS.VIEW_TASKS), true);
  assert.equal(can(ROLE_NAMES.MEMBER, PERMISSIONS.WRITE_TASKS), false);
  assert.equal(can(ROLE_NAMES.MEMBER, PERMISSIONS.MANAGE_USERS_ROLES), false);
  assert.equal(can(ROLE_NAMES.MEMBER, PERMISSIONS.MANAGE_TEAMS), false);
});

runTest("Unknown roles have no access", () => {
  assert.equal(can("RandomRole", PERMISSIONS.VIEW_TASKS), false);
  assert.equal(can(null, PERMISSIONS.VIEW_TASKS), false);
});

runTest("buildPermissions returns expected view model for templates", () => {
  assert.deepEqual(buildPermissions(ROLE_NAMES.ADMIN), {
    canViewTasks: false,
    canWriteTasks: false,
    canManageUsersRoles: true,
    canManageTeams: false,
    canManageOwnTeam: false
  });

  assert.deepEqual(buildPermissions(ROLE_NAMES.EDITOR), {
    canViewTasks: true,
    canWriteTasks: true,
    canManageUsersRoles: false,
    canManageTeams: false,
    canManageOwnTeam: false
  });

  assert.deepEqual(buildPermissions(ROLE_NAMES.VIEWER), {
    canViewTasks: true,
    canWriteTasks: false,
    canManageUsersRoles: false,
    canManageTeams: false,
    canManageOwnTeam: false
  });

  assert.deepEqual(buildPermissions(ROLE_NAMES.TEAM_LEADER), {
    canViewTasks: true,
    canWriteTasks: true,
    canManageUsersRoles: false,
    canManageTeams: false,
    canManageOwnTeam: true
  });

  assert.deepEqual(buildPermissions(ROLE_NAMES.PERSONAL_ACCOUNT), {
    canViewTasks: true,
    canWriteTasks: false,
    canManageUsersRoles: false,
    canManageTeams: false,
    canManageOwnTeam: false
  });

  assert.deepEqual(buildPermissions(ROLE_NAMES.MEMBER), {
    canViewTasks: true,
    canWriteTasks: false,
    canManageUsersRoles: false,
    canManageTeams: false,
    canManageOwnTeam: false
  });
});

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log("All authorization tests passed.");
