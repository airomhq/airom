'use strict';
const Select = require('./select');
class AutoComplete extends Select {
  constructor(options) { super(options); this.cursorShow(); }
}
module.exports = AutoComplete;
