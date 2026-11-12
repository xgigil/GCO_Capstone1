function getRequiredDomainByRole(role) {
    if (role === "student") return "my.xu.edu.ph";
    if (role === "counselor" || role === "admin") return "xu.edu.ph";
    return null;
  }
  
  // Exactly one "@", dotted domain, no whitespace.
  const EMAIL_RE =
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
  
  function normalizeEmail(raw) {
    if (typeof raw !== "string") return null;
    const email = raw.trim().toLowerCase();
    if (email.length > 254 || !EMAIL_RE.test(email)) return null;
    return email;
  }
  
  function getEmailDomain(email) {
    const at = email.indexOf("@");
    if (at < 1 || at !== email.lastIndexOf("@")) return null;
    return email.slice(at + 1);
  }
  
  function matchesRoleDomain(rawEmail, role) {
    const required = getRequiredDomainByRole(role);
    if (!required) return false;
    const email = normalizeEmail(rawEmail);
    if (!email) return false;
    return getEmailDomain(email) === required.toLowerCase();
  }
  
  module.exports = {
    getRequiredDomainByRole,
    normalizeEmail,
    getEmailDomain,
    matchesRoleDomain
  };