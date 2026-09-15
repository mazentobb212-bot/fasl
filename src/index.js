const SESSION_DAYS = 30;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function bad(message, status = 400) {
  return json({ success: false, error: message }, status);
}

function randomId() {
  return crypto.randomUUID();
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function bytesToHex(bytes) {
  return [...bytes]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 120000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return bytesToBase64(new Uint8Array(bits));
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  return {
    salt: bytesToBase64(salt),
    hash: await hashPassword(password, salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const salt = base64ToBytes(storedSalt);
  const hash = await hashPassword(password, salt);

  return hash === storedHash;
}

async function hashSessionToken(token) {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

function getToken(request) {
  const header = request.headers.get("Authorization");

  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

async function getUser(request, env) {
  const token = getToken(request);

  if (!token) return null;

  const tokenHash = await hashSessionToken(token);

  const session = await env.DB.prepare(`
    SELECT
      sessions.user_id,
      users.username,
      users.email
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > datetime('now')
  `)
    .bind(tokenHash)
    .first();

  return session || null;
}

function validateUsername(username) {
  return /^[a-zA-Z0-9_]{3,20}$/.test(username);
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8;
}

async function register(request, env) {
  const body = await request.json();

  const username = String(body.username || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!validateUsername(username)) {
    return bad(
      "Username must be 3-20 characters and use only letters, numbers, or _."
    );
  }

  if (!validateEmail(email)) {
    return bad("Please enter a valid email.");
  }

  if (!validatePassword(password)) {
    return bad("Password must be at least 8 characters.");
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `)
    .bind(username, email)
    .first();

  if (existing) {
    return bad("Username or email is already registered.", 409);
  }

  const passwordData = await createPasswordHash(password);
  const userId = randomId();

  await env.DB.prepare(`
    INSERT INTO users (
      id,
      username,
      email,
      password_hash,
      password_salt
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      userId,
      username,
      email,
      passwordData.hash,
      passwordData.salt
    )
    .run();

  return json({
    success: true,
    message: "Account created successfully!",
    user: {
      id: userId,
      username,
      email
    }
  }, 201);
}

async function login(request, env) {
  const body = await request.json();

  const loginValue = String(body.login || "").trim();
  const password = String(body.password || "");

  if (!loginValue || !password) {
    return bad("Please enter your username/email and password.");
  }

  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
      email,
      password_hash,
      password_salt
    FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `)
    .bind(loginValue, loginValue.toLowerCase())
    .first();

  if (!user) {
    return bad("Invalid username/email or password.", 401);
  }

  const correct = await verifyPassword(
    password,
    user.password_hash,
    user.password_salt
  );

  if (!correct) {
    return bad("Invalid username/email or password.", 401);
  }

  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64(tokenBytes);
  const tokenHash = await hashSessionToken(token);

  const expires = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions (
      token_hash,
      user_id,
      expires_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(tokenHash, user.id, expires)
    .run();

  return json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });
}

async function logout(request, env) {
  const token = getToken(request);

  if (token) {
    const tokenHash = await hashSessionToken(token);

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
      .bind(tokenHash)
      .run();
  }

  return json({
    success: true,
    message: "Logged out."
  });
}

async function me(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return bad("Not logged in.", 401);
  }

  return json({
    success: true,
    user: {
      id: user.user_id,
      username: user.username,
      email: user.email
    }
  });
}

async function createPost(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return bad("You must be logged in.", 401);
  }

  const body = await request.json();

  const text = String(body.body || "").trim();
  const anonymous = Boolean(body.is_anonymous);

  if (!text) {
    return bad("Post cannot be empty.");
  }

  if (text.length > 5000) {
    return bad("Post is too long.");
  }

  const postId = randomId();

  await env.DB.prepare(`
    INSERT INTO posts (
      id,
      author_id,
      body,
      is_anonymous
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      postId,
      user.user_id,
      text,
      anonymous ? 1 : 0
    )
    .run();

  return json({
    success: true,
    post: {
      id: postId,
      body: text,
      is_anonymous: anonymous,
      username: anonymous ? "مجهول" : user.username,
      likes: 0,
      comments: 0
    }
  }, 201);
}

async function getPosts(request, env) {
  const result = await env.DB.prepare(`
    SELECT
      posts.id,
      posts.body,
      posts.is_anonymous,
      posts.created_at,
      CASE
        WHEN posts.is_anonymous = 1 THEN 'مجهول'
        ELSE users.username
      END AS username,

      (
        SELECT COUNT(*)
        FROM likes
        WHERE likes.post_id = posts.id
      ) AS likes,

      (
        SELECT COUNT(*)
        FROM comments
        WHERE comments.post_id = posts.id
      ) AS comments

    FROM posts
    JOIN users ON users.id = posts.author_id
    WHERE posts.status IS NULL OR posts.status = 'approved'
    ORDER BY posts.created_at DESC
    LIMIT 50
  `).all();

  return json({
    success: true,
    posts: result.results || []
  });
}

async function likePost(request, env, postId) {
  const user = await getUser(request, env);

  if (!user) {
    return bad("You must be logged in.", 401);
  }

  const post = await env.DB.prepare(`
    SELECT id
    FROM posts
    WHERE id = ?
  `)
    .bind(postId)
    .first();

  if (!post) {
    return bad("Post not found.", 404);
  }

  const existing = await env.DB.prepare(`
    SELECT post_id
    FROM likes
    WHERE post_id = ? AND user_id = ?
  `)
    .bind(postId, user.user_id)
    .first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM likes
      WHERE post_id = ? AND user_id = ?
    `)
      .bind(postId, user.user_id)
      .run();
  } else {
    await env.DB.prepare(`
      INSERT INTO likes (
        post_id,
        user_id
      )
      VALUES (?, ?)
    `)
      .bind(postId, user.user_id)
      .run();
  }

  const count = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM likes
    WHERE post_id = ?
  `)
    .bind(postId)
    .first();

  return json({
    success: true,
    liked: !existing,
    likes: count.count
  });
}

async function addComment(request, env, postId) {
  const user = await getUser(request, env);

  if (!user) {
    return bad("You must be logged in.", 401);
  }

  const body = await request.json();
  const text = String(body.body || "").trim();

  if (!text) {
    return bad("Comment cannot be empty.");
  }

  if (text.length > 2000) {
    return bad("Comment is too long.");
  }

  const post = await env.DB.prepare(`
    SELECT id
    FROM posts
    WHERE id = ?
  `)
    .bind(postId)
    .first();

  if (!post) {
    return bad("Post not found.", 404);
  }

  const commentId = randomId();

  await env.DB.prepare(`
    INSERT INTO comments (
      id,
      post_id,
      author_id,
      body
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      commentId,
      postId,
      user.user_id,
      text
    )
    .run();

  return json({
    success: true,
    comment: {
      id: commentId,
      post_id: postId,
      username: user.username,
      body: text
    }
  }, 201);
}

async function getComments(request, env, postId) {
  const result = await env.DB.prepare(`
    SELECT
      comments.id,
      comments.body,
      comments.created_at,
      users.username
    FROM comments
    JOIN users ON users.id = comments.author_id
    WHERE comments.post_id = ?
      AND (comments.status IS NULL OR comments.status = 'approved')
    ORDER BY comments.created_at ASC
    LIMIT 100
  `)
    .bind(postId)
    .all();

  return json({
    success: true,
    comments: result.results || []
  });
}

async function reportPost(request, env, postId) {
  const user = await getUser(request, env);

  if (!user) {
    return bad("You must be logged in.", 401);
  }

  const body = await request.json();
  const reason = String(body.reason || "").trim();

  if (!reason) {
    return bad("Please provide a report reason.");
  }

  const reportId = randomId();

  await env.DB.prepare(`
    INSERT INTO reports (
      id,
      reporter_id,
      post_id,
      reason
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      reportId,
      user.user_id,
      postId,
      reason.slice(0, 500)
    )
    .run();

  return json({
    success: true,
    message: "Report submitted."
  }, 201);
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const method = request.method;

      if (method === "OPTIONS") {
        return new Response(null, { status: 204 });
      }

      if (url.pathname === "/api/health") {
        return json({
          success: true,
          message: "FASL API is working! 🇪🇬"
        });
      }

      if (url.pathname === "/api/register" && method === "POST") {
        return await register(request, env);
      }

      if (url.pathname === "/api/login" && method === "POST") {
        return await login(request, env);
      }

      if (url.pathname === "/api/logout" && method === "POST") {
        return await logout(request, env);
      }

      if (url.pathname === "/api/me" && method === "GET") {
        return await me(request, env);
      }

      if (url.pathname === "/api/posts" && method === "GET") {
        return await getPosts(request, env);
      }

      if (url.pathname === "/api/posts" && method === "POST") {
        return await createPost(request, env);
      }

      const likeMatch = url.pathname.match(
        /^\/api\/posts\/([^/]+)\/like$/
      );

      if (likeMatch && method === "POST") {
        return await likePost(request, env, likeMatch[1]);
      }

      const commentsMatch = url.pathname.match(
        /^\/api\/posts\/([^/]+)\/comments$/
      );

      if (commentsMatch && method === "GET") {
        return await getComments(request, env, commentsMatch[1]);
      }

      if (commentsMatch && method === "POST") {
        return await addComment(request, env, commentsMatch[1]);
      }

      const reportMatch = url.pathname.match(
        /^\/api\/posts\/([^/]+)\/report$/
      );

      if (reportMatch && method === "POST") {
        return await reportPost(request, env, reportMatch[1]);
      }

      return bad("Route not found.", 404);

    } catch (error) {
      console.error(error);

      return json({
        success: false,
        error: "Server error."
      }, 500);
    }
  }
};
