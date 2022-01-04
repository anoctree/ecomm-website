const { check } = require('express-validator');
const usersRepo = require('../../repositories/users');

module.exports = {
    requireTitle: check('title').trim()
    .isLength({ min: 5, max: 50 })
    .withMessage('Must be between 5 & 50 characters'),
    requirePrice: check('price').trim()
    .toFloat().isFloat({ min: 1 })
    .withMessage('Must be between 5 & 50 characters'),
    requireEmail: check('email').trim()
    .normalizeEmail().isEmail().withMessage('Must be a valid email')
    .custom(async (email)=>{
        const existingUser = await usersRepo.getOneBy({ email });
        if (existingUser) {
            throw new Error("Email in use");
        }
    }),
    requirePassword: check('password').trim()
    .isLength({ min:4, max:12 }).withMessage('Must be between 4 & 12 characters'),
    requirePasswordConfirmation: check('passwordConfirmation').trim()
    .isLength({ min:4, max:12 }).withMessage('Must be between 4 & 12 characters')
    .custom((passwordConfirmation, {req})=>{
        if (req.body.password !== passwordConfirmation) {
            throw new Error("Passwords must match");
        }
    }),
    requireEmailExists: check('email').trim().normalizeEmail()
    .isEmail().withMessage('Must provide a valid email')
    .custom(async email => {
        const user = await usersRepo.getOneBy({ email });
        if (!user) {
            throw new Error("Email not found");
        }
    }),
    requireValidPasswordForUser: check('password').trim()
    .custom(async (password, {req}) => {
        const user = await usersRepo.getOneBy({ email: req.body.email });
        if (!user) {
            throw new Error("Incorrect password");
        }
        const validPassword = await usersRepo.comparePasswords(user.password, password);
        if (!validPassword) {
            throw new Error("Incorrect password");
        }
    })

}