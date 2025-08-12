import jwt from 'jsonwebtoken';

export const onlyadmin = async (req, res, next) => {
    try {
        const token = req.cookies.access_token;
        if (!token) {
            return res.status(403).json({ success: false, message: 'Unauthorized: No token' });
        }

        const decodeToken = jwt.verify(token, process.env.JWT_SECRET);

        if (decodeToken.role === 'admin') {
            req.user = decodeToken;
            next();
        } else {
            return res.status(403).json({ success: false, message: 'Unauthorized: Not admin' });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
