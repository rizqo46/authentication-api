const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const tokenSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: "user",
  },
  requestType: {
    type: String,
    required: true,
    enum: ['Register', 'Forgot'],
    default: 'Register'
  },
  token: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    expires: function(){
      if (this.requestType === 'Register') {
        return 3600 * 24 // a day
      }
      return 60 * 5 // 5 minutes
    },
  },
});

tokenSchema.statics.verify =  async function (userId, PIN) {
    const token = await this.findOne({userId});
    if (token) {
        const auth = await bcrypt.compare(PIN, token.token);
        if (auth) {
             return token;
        }
        throw Error('PIN is wrong');
        
    }
    throw Error('User dont has token');
};

module.exports = mongoose.model("Token", tokenSchema);