// Freeze Object.prototype without breaking the "override mistake" (SES-style override taming).
//
// Tauri's own `app.security.freezePrototype` runs `Object.freeze(Object.prototype)` as is.
// After that, plain assignment of an inherited name on an ordinary object, such as
// `ns.toString = fn` (which @xterm/xterm does while its module loads), throws in strict
// code, so the app's bundle fails to start. Here each data property of Object.prototype is
// first turned into an accessor whose getter returns the original value and whose setter
// defines an own property on the receiver (what the assignment would have done had the
// prototype not been frozen), then Object.prototype is frozen. The prototype itself stays
// unmodifiable: no property can be added, removed, redefined or set on it.
(function () {
  'use strict';
  var proto = Object.prototype;
  var names = Object.getOwnPropertyNames(proto);
  for (var i = 0; i < names.length; i++) {
    var desc = Object.getOwnPropertyDescriptor(proto, names[i]);
    if (!desc || !('value' in desc) || !desc.configurable) continue;
    (function (name, value, enumerable) {
      Object.defineProperty(proto, name, {
        get: function () {
          return value;
        },
        set: function (next) {
          if (this === proto) throw new TypeError('Object.prototype is frozen');
          Object.defineProperty(this, name, { value: next, writable: true, enumerable: true, configurable: true });
        },
        enumerable: enumerable,
        configurable: false,
      });
    })(names[i], desc.value, desc.enumerable);
  }
  Object.freeze(proto);
})();
