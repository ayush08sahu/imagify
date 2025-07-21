import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    // Try to get token from 'authorization' or 'x-access-token' headers
    const token = req.headers['token'] || req.headers['x-access-token'];
    if (!token) {
        console.error('No token provided in headers.');
        return res.status(401).json({ success: false, message: 'Not Authorized. No token provided.' });
    }
    if (!process.env.JWT_SECRET) {
        console.error('JWT_SECRET is not set in environment variables.');
        return res.status(500).json({ success: false, message: 'Server configuration error. Please contact admin.' });
    }
    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        if (tokenDecode.id) {
            req.userId = tokenDecode.id;
            next();
        } else {
            console.error('Token decoded but no id found in payload:', tokenDecode);
            return res.status(401).json({ success: false, message: 'Not Authorized. Invalid token payload.' });
        }
    } catch (error) {
        console.error('JWT verification error:', error.message);
        res.status(401).json({ success: false, message: 'Invalid or expired token: ' + error.message });
    }
}

export default userAuth;