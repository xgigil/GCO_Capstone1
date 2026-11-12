/**
 * TEST SUITE: Exact email-domain check (auth.js)
 *
 * Covers the security fix that replaced the old "ends with @xu.edu.ph" check
 * with: clean up the email first, then compare the domain exactly.
 *   - students:           must use @my.xu.edu.ph
 *   - counselors/admins:  must use @xu.edu.ph
 *
 * Output format matches the other system tests:
 * Test ID | Description | Expected Outcome | Observed Outcome | Result
 */
const {
    normalizeEmail,
    getEmailDomain,
    matchesRoleDomain
} = require("../server/utils/emailDomain");
  
  const SYSTEM_NAME = process.env.TEST_SYSTEM_NAME || "GCO Counseling Appointment Management System";
  const BRANCH = process.env.TEST_BRANCH || "feature/user-management";
  
  function padRight(s, n) {
    const v = String(s ?? "");
    return v.length >= n ? v.slice(0, n - 1) + "…" : v + " ".repeat(n - v.length);
  }
  
  // Small helpers so each test reads like plain English.
  const allowed = (v) => ({ pass: v === true, observed: v === true ? "Allowed" : "Blocked (should be allowed)" });
  const blocked = (v) => ({ pass: v === false, observed: v === false ? "Blocked" : "Allowed (should be blocked)" });
  const returned = (v, want) => ({ pass: v === want, observed: `Returned ${JSON.stringify(v)}` });
  
  function runTest(test) {
    try {
      const out = test.run();
      return {
        id: test.id,
        description: test.description,
        expected: test.expected,
        observed: out.observed || "",
        result: out.pass ? "PASSED" : "FAILED"
      };
    } catch (e) {
      return {
        id: test.id,
        description: test.description,
        expected: test.expected,
        observed: `Error: ${e.message}`,
        result: "FAILED"
      };
    }
  }
  
  function printReport(title, rows) {
    console.log("");
    console.log(title);
    console.log(`System: ${SYSTEM_NAME}`);
    console.log(`Branch: ${BRANCH}`);
    console.log("");
    console.log(
      [
        padRight("Test ID", 8),
        padRight("Description", 42),
        padRight("Expected Outcome", 40),
        padRight("Observed Outcome", 40),
        padRight("Result", 7)
      ].join(" | ")
    );
    console.log("-".repeat(152));
    for (const r of rows) {
      console.log(
        [
          padRight(r.id, 8),
          padRight(r.description, 42),
          padRight(r.expected, 40),
          padRight(r.observed, 40),
          padRight(r.result, 7)
        ].join(" | ")
      );
    }
  }
  
  let passed = 0;
  let failed = 0;
  
  function runSuite(title, tests) {
    const rows = tests.map(runTest);
    for (const r of rows) {
      if (r.result === "PASSED") passed += 1;
      else failed += 1;
    }
    printReport(title, rows);
  }
  
  console.log("EMAIL DOMAIN CHECK TESTING: auth.js");
  console.log("Change: 'ends with' check -> clean up email + exact domain match");
  console.log(`Date: ${new Date().toISOString()}`);
  
  // ---------------- CLEAN-UP (normalizeEmail) ----------------
  const cleanUpTests = [
    {
      id: 1,
      description: "Tidy up spaces and capital letters",
      expected: "Lowercase email with no extra spaces",
      run: () => returned(normalizeEmail("  Sir.Bobby@XU.EDU.PH "), "sir.bobby@xu.edu.ph")
    },
    {
      id: 2,
      description: "Reject address with two @ signs",
      expected: "Email should be rejected (null)",
      run: () => returned(normalizeEmail("user@gmail.com@xu.edu.ph"), null)
    },
    {
      id: 3,
      description: "Reject empty or non-text input",
      expected: "Email should be rejected (null)",
      run: () => {
        const all = [normalizeEmail(""), normalizeEmail(null), normalizeEmail(123)];
        return { pass: all.every((v) => v === null), observed: all.every((v) => v === null) ? "All rejected" : "Some accepted" };
      }
    },
    {
      id: 4,
      description: "Reject text that is not an email",
      expected: "Email should be rejected (null)",
      run: () => {
        const all = [normalizeEmail("not-an-email"), normalizeEmail("@xu.edu.ph"), normalizeEmail("a@xu")];
        return { pass: all.every((v) => v === null), observed: all.every((v) => v === null) ? "All rejected" : "Some accepted" };
      }
    }
  ];
  
  // ---------------- DOMAIN READER (getEmailDomain) ----------------
  const domainReaderTests = [
    {
      id: 1,
      description: "Read the domain of a student email",
      expected: "Returns my.xu.edu.ph",
      run: () => returned(getEmailDomain("a@my.xu.edu.ph"), "my.xu.edu.ph")
    },
    {
      id: 2,
      description: "Read the domain of a staff email",
      expected: "Returns xu.edu.ph",
      run: () => returned(getEmailDomain("a@xu.edu.ph"), "xu.edu.ph")
    },
    {
      id: 3,
      description: "Keep a subdomain separate",
      expected: "Returns mail.xu.edu.ph (not xu.edu.ph)",
      run: () => returned(getEmailDomain("a@mail.xu.edu.ph"), "mail.xu.edu.ph")
    },
    {
      id: 4,
      description: "Read the domain of a Gmail address",
      expected: "Returns gmail.com",
      run: () => returned(getEmailDomain("someone@gmail.com"), "gmail.com")
    },
    {
      id: 5,
      description: "No domain for address with two @ signs",
      expected: "Returns null",
      run: () => returned(getEmailDomain("user@gmail.com@xu.edu.ph"), null)
    }
  ];
  
  // ---------------- ROLE RULES (matchesRoleDomain) ----------------
  const roleRuleTests = [
    {
      id: 1,
      description: "Student email accepted for a student",
      expected: "Allowed",
      run: () => allowed(matchesRoleDomain("20230028304@my.xu.edu.ph", "student"))
    },
    {
      id: 2,
      description: "Staff email refused for a student",
      expected: "Blocked",
      run: () => blocked(matchesRoleDomain("faculty@xu.edu.ph", "student"))
    },
    {
      id: 3,
      description: "Gmail refused for a student",
      expected: "Blocked",
      run: () => blocked(matchesRoleDomain("user@gmail.com", "student"))
    },
    {
      id: 4,
      description: "Look-alike student domain refused",
      expected: "Blocked (user@evil.my.xu.edu.ph)",
      run: () => blocked(matchesRoleDomain("user@evil.my.xu.edu.ph", "student"))
    },
    {
      id: 5,
      description: "Staff email accepted for a counselor",
      expected: "Allowed",
      run: () => allowed(matchesRoleDomain("counselor@xu.edu.ph", "counselor"))
    },
    {
      id: 6,
      description: "Staff email accepted for an admin",
      expected: "Allowed",
      run: () => allowed(matchesRoleDomain("admin@xu.edu.ph", "admin"))
    },
    {
      id: 7,
      description: "Student email refused for a counselor",
      expected: "Blocked",
      run: () => blocked(matchesRoleDomain("student@my.xu.edu.ph", "counselor"))
    },
    {
      id: 8,
      description: "Gmail refused for an admin",
      expected: "Blocked",
      run: () => blocked(matchesRoleDomain("user@gmail.com", "admin"))
    },
    {
      id: 9,
      description: "Look-alike staff domain refused",
      expected: "Blocked (user@evilxu.edu.ph)",
      run: () => blocked(matchesRoleDomain("user@evilxu.edu.ph", "counselor"))
    },
    {
      id: 10,
      description: "Subdomain refused for a counselor",
      expected: "Blocked (user@mail.xu.edu.ph)",
      run: () => blocked(matchesRoleDomain("user@mail.xu.edu.ph", "counselor"))
    },
    {
      id: 11,
      description: "Two-@ trick refused for a counselor",
      expected: "Blocked (user@gmail.com@xu.edu.ph)",
      run: () => blocked(matchesRoleDomain("user@gmail.com@xu.edu.ph", "counselor"))
    },
    {
      id: 12,
      description: "Capitals and spaces still accepted",
      expected: "Allowed ( Counselor@XU.EDU.PH )",
      run: () => allowed(matchesRoleDomain("  Counselor@XU.EDU.PH ", "counselor"))
    },
    {
      id: 13,
      description: "Unknown role refused",
      expected: "Blocked",
      run: () => blocked(matchesRoleDomain("a@xu.edu.ph", "superuser"))
    },
    {
      id: 14,
      description: "Empty or missing email refused",
      expected: "Blocked",
      run: () => {
        const all = [matchesRoleDomain("", "admin"), matchesRoleDomain(null, "admin")];
        return { pass: all.every((v) => v === false), observed: all.every((v) => v === false) ? "Blocked" : "Allowed (should be blocked)" };
      }
    }
  ];
  
  runSuite("EMAIL CLEAN-UP TEST REPORT (normalizeEmail)", cleanUpTests);
  runSuite("DOMAIN READER TEST REPORT (getEmailDomain)", domainReaderTests);
  runSuite("ROLE DOMAIN RULES TEST REPORT (matchesRoleDomain)", roleRuleTests);
  
  console.log("");
  console.log(`Summary: ${passed} passed, ${failed} failed`);
  console.log("DONE");
  process.exit(failed ? 1 : 0);