// in auth.js

const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = (req, res, next) => {
  const password = req.body.password;
  argon2
    .hash(password, hashingOptions)
    .then((hashedPassword) => {
      req.body.hashedPassword = hashedPassword;
      delete req.body.password;
      console.log("password successfully hashed");
      next();
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const verifyPassword = async (req, res) => {
  const plainPassword = req.body.password;
  const hashedPassword = req.user.hashedPassword;

  try {
    if (await argon2.verify(hashedPassword, plainPassword)) {
      const payload = { sub: req.user.id };
      const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      delete req.user.hashedPassword;
      res.json({ ...req.user, accessToken: accessToken });
    } else {
      res.status(401).send("Password did not match");
    }
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
};

const verifyToken = (req, res, next) => {
  try {
    const authHeader = req.get("authorization");
    // console.log(authHeader);

    if (!authHeader) {
      throw new Error("Authorization header is missing");
    }

    const [type, token] = authHeader.split(" ");

    if (type !== "Bearer") {
      throw new Error("Authorization header has not the 'Bearer' type");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.payload = decoded;
    console.log(req.payload);
    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

const verifyUser = (req, res, next) => {
  const tokenUserId = req.payload.sub;
  const userId = parseInt(req.params.id, 10);

  try {
    if (tokenUserId === userId) {
      console.log("your Id's match, you can go to the next step");
      next();
    } else {
      res.status(403).send("You are not allowed to modify this users details");
    }
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
  verifyUser,
};
