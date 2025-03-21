function ensureAuthenticated(req, res, next) {
    if (!req.user) {
        return res.redirect("/login"); // Redirect to login if not authenticated
    }
    next();
}

function ensureAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).send("Access Denied: Admins Only");
    }
    next();
}

module.exports = { ensureAuthenticated, ensureAdmin };
