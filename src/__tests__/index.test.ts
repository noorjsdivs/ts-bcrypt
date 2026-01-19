import bcrypt from "../index";

describe("ts-bcrypt compatibility tests", () => {
  const password = "mySecurePassword123!";

  describe("Hashing", () => {
    test("hash (async promise)", async () => {
      const hash = await bcrypt.hash(password, 10);
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    test("hash (async callback)", (done) => {
      bcrypt.hash(password, 10, (err, hash) => {
        expect(err).toBeNull();
        expect(hash).toBeDefined();
        expect(typeof hash).toBe("string");
        done();
      });
    });

    test("hashSync", () => {
      const hash = bcrypt.hashSync(password, 10);
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    test("hash with separate salt generation", async () => {
      const salt = await bcrypt.genSalt(10);
      const parts = salt.split("$");
      const saltHex = parts[1]; // iterations$salt
      const hash = await bcrypt.hash(password, salt);
      expect(hash).toContain(saltHex);
    });
  });

  describe("Comparison", () => {
    test("compare (async promise) - true", async () => {
      const hash = await bcrypt.hash(password, 10);
      const match = await bcrypt.compare(password, hash);
      expect(match).toBe(true);
    });

    test("compare (async promise) - false", async () => {
      const hash = await bcrypt.hash(password, 10);
      const match = await bcrypt.compare("wrongpassword", hash);
      expect(match).toBe(false);
    });

    test("compare (async callback) - true", (done) => {
      bcrypt.hash(password, 10).then((hash) => {
        bcrypt.compare(password, hash, (err, match) => {
          expect(err).toBeNull();
          expect(match).toBe(true);
          done();
        });
      });
    });

    test("compareSync - true", () => {
      const hash = bcrypt.hashSync(password, 10);
      const match = bcrypt.compareSync(password, hash);
      expect(match).toBe(true);
    });

    test("compareSync - false", () => {
      const hash = bcrypt.hashSync(password, 10);
      const match = bcrypt.compareSync("wrong", hash);
      expect(match).toBe(false);
    });
  });

  describe("Salt Generation", () => {
    test("genSalt (async promise)", async () => {
      const salt = await bcrypt.genSalt(10);
      expect(salt).toBeDefined();
      // Our custom format check or length check
      expect(salt.split("$").length).toBeGreaterThanOrEqual(2);
    });

    test("genSalt (async callback)", (done) => {
      bcrypt.genSalt(10, (err, salt) => {
        expect(err).toBeNull();
        expect(salt).toBeDefined();
        done();
      });
    });

    test("genSaltSync", () => {
      const salt = bcrypt.genSaltSync(10);
      expect(salt).toBeDefined();
    });
  });

  describe("Utilities", () => {
    test("getRounds", async () => {
      const hash = await bcrypt.hash(password, 12); // Use 12 rounds
      const rounds = bcrypt.getRounds(hash);
      // Logic in genSalt turns small numbers into defaults or powers?
      // Our implementation currently sets iterations = rounds if rounds > 50, else pow(2, rounds).
      // 12 -> 4096.
      expect(rounds).toBe(4096);
    });

    test("isStrongPassword", () => {
      expect(bcrypt.isStrongPassword(password)).toBe(true);
      expect(bcrypt.isStrongPassword("weak")).toBe(false);
    });

    test("generateSecurePassword", () => {
      const pass = bcrypt.generateSecurePassword(16);
      expect(pass.length).toBe(16);
    });
  });
});
