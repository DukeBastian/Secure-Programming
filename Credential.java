package ee.taltech.secprog.pm;

/** One stored login. A record is immutable: to change it, replace it. */
record Credential(String service, String username, String password) {}
