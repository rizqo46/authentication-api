const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
const {isEmail} = require('validator');
const keys = require('../configs/keys');

const userSchema = new Schema({
    googleID:{
        type: String,
        trim: true,
        unique: true,
        sparse: true
    },
    email: {
        type: String,
        trim: true,
        require: [true, "Please enter an email"],
        unique: [true, "Email already registered"],
        lowercase: true,
        validate: [isEmail, 'Please enter valid email']
    },
    lastLogin: {
        type: Date,
        required: true,
        default: Date.now,
    },
    status: {
        type: String, 
        enum: ['Pending', 'Active'],
        default: 'Pending'
    },
    password: {
        type: String,
        require: function(){
            if (this.googleID) {
                return false
            }

            return [true, "Please enter a password"]
        },
        minLength: [8, 'Minimum pass length is 8']
    }
}, { timestamps: true });


userSchema.pre('save', async function (next) {
    if (this.isNew) {
        if (this.password) {
            this.password = await bcrypt.hash(this.password, keys.bcrypt.saltRound);
        }
    }
    next();
});

// userSchema.pre('updateOne', async function (next) {
//     console.log(this.isModified('this.password'));
//     if (this.isModified('this.password')) {
//         this.password = await bcrypt.hash(this.password, keys.bcrypt.saltRound);
//     }
//     next();
// });

userSchema.statics.login =  async function (email, password) {
    if (typeof email !== "string") {
        throw new Error('email is not string');
    }

    const user = await this.findOne({email})
    if (user) {
        if (typeof password !== "string") {
            throw new Error('password must be string');
        }
        if (user.password) {
            const auth = await bcrypt.compare(password, user.password);
            if (auth) {
                user.lastLogin = Date.now();
                user.save();
                return user;
            }
            throw new Error('password is incorrect');
        }
        
    }
    throw new Error('email is not registered');
};

userSchema.statics.loginGoogle =  async function (googleID) {
    const user = await this.findOne({googleID});
    if (user) {
        user.lastLogin = Date.now();
        user.save();
        return user
    }
    throw new Error('GoogleID is not registered');
};

const User = mongoose.model('User', userSchema);

module.exports = User;