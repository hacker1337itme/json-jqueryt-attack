# json-jqueryt-attack
json &amp;&amp; jqury bugs 


## JSON Type Confusion Attacks

### 1. **Type Juggling & Coercion**

```javascript
// Vulnerable authentication check
const userData = JSON.parse(userInput);
if (userData.isAdmin == true) {  // Loose comparison
    grantAdminAccess();
}

// Attack payload
{"isAdmin": "true"}     // String passes == comparison
{"isAdmin": 1}          // Number passes
{"isAdmin": "anything"} // Non-empty string is truthy
```

**Safe approach:**
```javascript
if (userData.isAdmin === true) {  // Strict comparison
    grantAdminAccess();
}
```

### 2. **Numeric Type Confusion**

```javascript
// Vulnerable - price validation
const order = JSON.parse(userInput);
const total = order.quantity * order.price;
if (total < 1000) {
    processPayment(total);
}

// Attack payloads
{"quantity": "1000000", "price": "999"}  // String multiplication = NaN
{"quantity": [], "price": 100}           // Array coerces to 0
{"quantity": null, "price": 100}         // null = 0
{"quantity": {}, "price": 100}           // Object = NaN
```

**Safe approach:**
```javascript
function validateNumber(value, defaultValue = 0) {
    const num = Number(value);
    return isNaN(num) ? defaultValue : num;
}

const order = JSON.parse(userInput);
const quantity = validateNumber(order.quantity);
const price = validateNumber(order.price);
```

### 3. **Array/Object Confusion**

```javascript
// Vulnerable - expects array
function processItems(items) {
    items.forEach(item => {  // Will throw if not array
        updateInventory(item);
    });
}

// Attack payload
{"items": {"__proto__": {"malicious": true}}}  // Object with forEach?

// Safe approach
function processItems(items) {
    if (!Array.isArray(items)) {
        items = [items];  // Or throw error
    }
    items.forEach(item => updateInventory(item));
}
```

### 4. **Null & Undefined Confusion**

```javascript
// Vulnerable
const config = JSON.parse(userInput);
const timeout = config.timeout || 5000;  // 0 becomes 5000

// Attack payloads
{"timeout": 0}        // Should be 0, becomes 5000
{"timeout": null}     // Becomes 5000
{"timeout": false}    // Becomes 5000
```

**Safe approach:**
```javascript
const timeout = config.timeout !== undefined ? config.timeout : 5000;
```

### 5. **Prototype Pollution via __proto__**

```javascript
// Vulnerable merge function
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

const config = JSON.parse(userInput);
merge(defaultConfig, config);

// Attack payload
{"__proto__": {"isAdmin": true, "polluted": true}}
```

**Mitigation:**
```javascript
function safeMerge(target, source) {
    const safeTarget = Object.create(null);
    for (let key in source) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            safeTarget[key] = source[key];
        }
    }
    return Object.assign(target, safeTarget);
}
```

### 6. **Type Confusion in Deserialization**

```javascript
// Vulnerable custom reviver
JSON.parse(userInput, function(key, value) {
    if (value && value.type === 'Date') {
        return new Date(value.value);  // Type confusion here
    }
    return value;
});

// Attack payload
{"type": "Date", "value": "<script>alert('xss')</script>"}
// Creates Date object with malicious string
```

### 7. **Boolean Confusion**

```javascript
// Vulnerable permission check
const user = JSON.parse(userInput);
if (user.isActive) {  // Any truthy value passes
    showSensitiveData();
}

// Attack payloads
{"isActive": "true"}     // String passes
{"isActive": 1}          // Number passes
{"isActive": []}         // Array passes
{"isActive": "false"}    // Non-empty string passes!
```

## Defense Strategies

### 1. **Schema Validation**
```javascript
const schema = {
    type: "object",
    properties: {
        id: { type: "number" },
        name: { type: "string" },
        items: { type: "array" },
        isActive: { type: "boolean" }
    },
    required: ["id", "name"]
};

function validateAgainstSchema(data, schema) {
    // Use libraries like ajv, joi, or zod
    const validate = ajv.compile(schema);
    if (!validate(data)) {
        throw new Error('Invalid data structure');
    }
    return data;
}
```

### 2. **Type Guard Functions**
```javascript
function assertType(value, expectedType) {
    const actualType = typeof value;
    if (actualType !== expectedType) {
        throw new TypeError(`Expected ${expectedType}, got ${actualType}`);
    }
    return value;
}

function assertArray(value) {
    if (!Array.isArray(value)) {
        throw new TypeError('Expected array');
    }
    return value;
}
```

### 3. **Safe Parsing with Strict Validation**
```javascript
function safeParseJSON(input, schema = null) {
    try {
        const parsed = JSON.parse(input);
        
        // Type checking for primitive values
        if (schema === 'array' && !Array.isArray(parsed)) {
            throw new Error('Expected array');
        }
        
        if (typeof schema === 'object' && schema !== null) {
            return validateAgainstSchema(parsed, schema);
        }
        
        return parsed;
    } catch (e) {
        console.error('JSON parsing failed:', e);
        return null;
    }
}
```

### 4. **Using JSON Schema Validators**
```javascript
// Using Zod for runtime type checking
import { z } from 'zod';

const UserSchema = z.object({
    id: z.number(),
    name: z.string(),
    isActive: z.boolean(),
    items: z.array(z.string())
});

const user = UserSchema.parse(JSON.parse(userInput));
```

## Attack Impact Examples

| Attack Type | Impact | Severity |
|------------|--------|----------|
| Type juggling | Authentication bypass | Critical |
| Numeric confusion | Price manipulation, DoS | High |
| Prototype pollution | Privilege escalation | Critical |
| Null confusion | Logic errors | Medium |
| Array/Object confusion | Application crash | Medium |
| Boolean confusion | Authorization bypass | High |

I'll document 50 distinct JSON type confusion and jQuery array manipulation vulnerabilities with specific examples.

## JSON TYPE CONFUSION BUGS (25)

### 1. **Loose Comparison with Null**
```javascript
if (userInput == null) {  // true for undefined and null
    grantAccess();  // Attacker sends undefined
}
```

### 2. **Empty Array Truthy Confusion**
```javascript
if (user.isAdmin) {  // [] is truthy
    elevatePrivileges();
}
// Payload: {"isAdmin": []}
```

### 3. **String to Number Coercion in Arithmetic**
```javascript
const total = price * quantity;  // "100" * "2" = 200
// But "100" * "2x" = NaN
```

### 4. **Object to Primitive Conversion**
```javascript
if (user.age > 18) {  // {valueOf: () => 999} passes
    allowAccess();
}
```

### 5. **Array Length Confusion**
```javascript
for (let i = 0; i < data.length; i++) {  // {length: 999999999}
    process(data[i]);  // Massive loop
}
```

### 6. **Prototype Chain Enumeration**
```javascript
for (let key in obj) {  // Includes __proto__, constructor
    obj[key] = sanitize(obj[key]);  // Pollutes prototype
}
```

### 7. **typeof Array Confusion**
```javascript
if (typeof items === 'object') {  // Arrays pass
    items.forEach(...);  // TypeError if object
}
```

### 8. **JSON.parse Reviver Injection**
```javascript
JSON.parse(input, (key, value) => {
    eval(value);  // RCE via reviver
    return value;
});
```

### 9. **NaN Comparison Bypass**
```javascript
if (total !== total) {  // NaN !== NaN is true
    // Never executes, bypassing validation
}
```

### 10. **Negative Zero Confusion**
```javascript
if (amount === 0) {  // -0 === 0 true
    // -0 bypasses positive checks
}
```

### 11. **Symbol Key Leakage**
```javascript
Object.keys(obj);  // Doesn't include Symbol keys
// Attacker hides data in Symbol properties
```

### 12. **Getter Injection**
```javascript
const config = JSON.parse(input);
const value = config.property;  // Getter could execute code
// Payload: {"get property()": "malicious"}
```

### 13. **Set/Map Serialization Confusion**
```javascript
const data = JSON.parse(input);
new Set(data);  // Expects iterable, but can cause issues
```

### 14. **BigInt Loss of Precision**
```javascript
const id = BigInt(json.id);  // Number loses precision
// Large numbers become corrupted
```

### 15. **RegExp Injection**
```javascript
new RegExp(userInput.pattern);  // ReDoS attack
// Payload: {"pattern": "(a+)+$"}
```

### 16. **Date Parsing Confusion**
```javascript
new Date(userInput.date);  // Invalid date = NaN
// Payload: {"date": "Invalid Date"}
```

### 17. **Function Serialization**
```javascript
eval('(' + userInput + ')');  // Direct RCE
// Payload: "function(){malicious()}"
```

### 18. **Proxy Traps Bypass**
```javascript
const validated = new Proxy(obj, {set: validate});
Object.assign(validated, malicious);  // Bypasses proxy
```

### 19. **WeakMap Key Confusion**
```javascript
weakMap.set(userInput, data);  // Only objects as keys
// Primitive keys cause TypeError
```

### 20. **Symbol.toPrimitive Hijacking**
```javascript
const obj = JSON.parse(input);
obj + '';  // Can execute arbitrary code
// Payload: {[Symbol.toPrimitive]: () => malicious()}
```

### 21. **Array Sort Comparator Injection**
```javascript
arr.sort(userInput.compare);  // Function injection
// Payload: {"compare": "function(){malicious()}"}
```

### 22. **JSON.stringify Replacer Attack**
```javascript
JSON.stringify(obj, userInput.replacer);  // Code execution
// Payload: {"replacer": "function(){malicious()}"}
```

### 23. **Object.is Comparison Confusion**
```javascript
if (Object.is(value, expected)) {  // NaN, -0 differences
    // Attacker uses edge cases
}
```

### 24. **Spread Operator Overload**
```javascript
const newObj = {...obj, ...userInput};  // Prototype pollution
// Payload: {"__proto__": {"polluted": true}}
```

### 25. **Reflect API Bypass**
```javascript
Reflect.set(obj, key, value);  // Bypasses property checks
// Can set dangerous properties
```

## JQUERY ARRAY MANIPULATION BUGS (25)

### 26. **$.each Non-Array Iteration**
```javascript
$.each(userInput, (i, val) => {  // Objects also iterate
    $('body').append(val);  // XSS via object values
});
```

### 27. **$.map String Coercion**
```javascript
const result = $.map(data, (val) => val.toString());
// [null] becomes [""], losing data
```

### 28. **$.grep Type Confusion**
```javascript
$.grep(items, (val) => val.active);  // undefined values
// "active" property missing causes issues
```

### 29. **$.inArray Type Sensitivity**
```javascript
$.inArray("5", [5]);  // Returns -1 (strict comparison)
// Type mismatch fails
```

### 30. **$.merge with Non-Arrays**
```javascript
$.merge(target, userInput);  // If userInput not array
// Corrupts target structure
```

### 31. **$.uniqueSort Callback Injection**
```javascript
$.uniqueSort(arr, userInput.comparator);  // Function injection
// Can execute arbitrary code
```

### 32. **$.makeArray Overload**
```javascript
$.makeArray(userInput);  // {length: 3} creates array
// Non-array objects with length property
```

### 33. **$.parseXML Entity Expansion**
```javascript
$.parseXML(userInput);  // Billion laughs attack
// XML entity expansion DoS
```

### 34. **$.param Recursion**
```javascript
$.param(userInput);  // Nested objects cause recursion
// {a:{b:{c:{...}}}} stack overflow
```

### 35. **$.extend Deep Clone Prototype**
```javascript
$.extend(true, {}, userInput);  // Prototype pollution
// Payload: {"__proto__": {"polluted": true}}
```

### 36. **$.fn.map Context Confusion**
```javascript
$('div').map(function() {
    return $(this).data(userInput);  // Data injection
});
```

### 37. **$.fn.each HTML Injection**
```javascript
$('div').each(function() {
    $(this).html(userInput);  // XSS
});
```

### 38. **$.fn.append Array Injection**
```javascript
$('div').append(userInput);  // If array, joins
// Can inject multiple malicious elements
```

### 39. **$.fn.data Type Confusion**
```javascript
$('div').data('key', userInput);
// Later retrieval expects specific type
```

### 40. **$.fn.attr Boolean Confusion**
```javascript
$('input').attr('disabled', userInput.disabled);
// "false" string enables input
```

### 41. **$.fn.val Array Confusion**
```javascript
$('select').val(userInput);  // Array for multi-select
// Single select with array bypasses validation
```

### 42. **$.fn.css Numeric Confusion**
```javascript
$('div').css('width', userInput.width);
// "100%", "100px", 100 all behave differently
```

### 43. **$.fn.animate Easing Injection**
```javascript
$('div').animate({left: 100}, userInput.easing);
// Can inject malicious easing function
```

### 44. **$.ajax Data Type Confusion**
```javascript
$.ajax({
    url: '/api',
    data: userInput,  // Object or string confusion
    dataType: 'json'  // Type confusion in response
});
```

### 45. **$.getJSON Callback Hijacking**
```javascript
$.getJSON(url, userInput.callback);  // JSONP callback
// Can execute arbitrary function
```

### 46. **$.Deferred Resolution Type**
```javascript
const dfd = $.Deferred();
dfd.resolve(userInput);  // Type confusion in handlers
// Handlers expect specific type
```

### 47. **$.when Non-Promise Confusion**
```javascript
$.when(userInput).done(handler);
// Non-promise objects handled differently
```

### 48. **$.proxy Context Confusion**
```javascript
$.proxy(userInput.fn, userInput.context);
// Can hijack execution context
```

### 49. **$.sub() Sandbox Escape**
```javascript
const sub$ = $.sub();
sub$.extend(true, {}, userInput);  // Sandbox escape
```

### 50. **$.holdReady State Confusion**
```javascript
$.holdReady(userInput.hold);
// Boolean confusion in ready state
```

## Complete Defense Example

```javascript
class SecureJSONHandler {
    static validateAndParse(input, schema) {
        try {
            // 1. Type validation
            if (typeof input !== 'string') {
                throw new Error('Input must be string');
            }
            
            // 2. Size limits
            if (input.length > 1024 * 1024) {
                throw new Error('Input too large');
            }
            
            // 3. Parse with limited reviver
            const parsed = JSON.parse(input, (key, value) => {
                // Block dangerous keys
                if (key === '__proto__' || key === 'constructor') {
                    return undefined;
                }
                return value;
            });
            
            // 4. Deep type checking
            return this.validateTypes(parsed, schema);
            
        } catch (e) {
            console.error('Validation failed:', e);
            return null;
        }
    }
    
    static validateTypes(obj, schema) {
        for (const [key, expectedType] of Object.entries(schema)) {
            const value = obj[key];
            const actualType = Array.isArray(value) ? 'array' : typeof value;
            
            if (actualType !== expectedType) {
                throw new Error(`Type mismatch for ${key}`);
            }
        }
        return obj;
    }
    
    static safeJQueryOperation($element, method, value) {
        // Escape HTML for any string values
        if (typeof value === 'string') {
            value = $('<div>').text(value).html();
        }
        return $element[method](value);
    }
}
```

# Comprehensive Testing Methodology for JSON Type Confusion & jQuery Array Bugs

## 1. **Automated Fuzzing Framework**

### 1.1 **Type Fuzzing Generator**
```javascript
class TypeFuzzer {
    constructor() {
        this.payloads = {
            primitives: [null, undefined, true, false, 0, 1, -0, NaN, Infinity, -Infinity, '', ' ', '0', 'false'],
            objects: [{}, [], {length: 0}, {length: 1000000}, {valueOf: () => 999}, {toString: () => 'malicious'}],
            special: ['__proto__', 'constructor', 'prototype', 'valueOf', 'toString', Symbol.iterator],
            malicious: [
                '{"__proto__": {"polluted": true}}',
                '{"constructor": {"prototype": {"polluted": true}}}',
                '<script>alert(1)</script>',
                'function(){malicious()}',
                '(a+)+$',
                '{"length": 999999999}'
            ]
        };
    }
    
    generateCombinations() {
        const combinations = [];
        for (const type1 of Object.values(this.payloads).flat()) {
            for (const type2 of Object.values(this.payloads).flat()) {
                combinations.push({
                    key: type1,
                    value: type2,
                    description: `Type confusion: ${typeof type1} -> ${typeof type2}`
                });
            }
        }
        return combinations;
    }
    
    async fuzzEndpoint(endpoint, method = 'POST') {
        const results = [];
        for (const payload of this.generateCombinations()) {
            try {
                const response = await fetch(endpoint, {
                    method: method,
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                results.push({
                    payload,
                    status: response.status,
                    success: response.ok
                });
            } catch (e) {
                results.push({payload, error: e.message});
            }
        }
        return this.analyzeResults(results);
    }
}
```

## 2. **Static Analysis Tools**

### 2.1 **ESLint Security Rules**
```javascript
// .eslintrc.js
module.exports = {
    plugins: ['security', 'no-unsafe-innerhtml'],
    rules: {
        'security/detect-object-injection': 'error',
        'security/detect-unsafe-regex': 'error',
        'no-eval': 'error',
        'no-implied-eval': 'error',
        'no-unsafe-innerhtml/no-unsafe-innerhtml': 'error',
        'security/detect-non-literal-regexp': 'error',
        'security/detect-non-literal-require': 'error'
    }
};
```

### 2.2 **Custom AST Scanner**
```javascript
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

class SecurityASTScanner {
    scanFile(code) {
        const ast = parser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript']
        });
        
        const vulnerabilities = [];
        
        traverse(ast, {
            CallExpression(path) {
                const callee = path.node.callee;
                
                // Check for unsafe JSON.parse
                if (callee.name === 'JSON.parse' && !this.hasTryCatch(path)) {
                    vulnerabilities.push({
                        type: 'Unsafe JSON.parse',
                        line: path.node.loc.start.line,
                        severity: 'HIGH'
                    });
                }
                
                // Check for jQuery array methods without validation
                if (callee.object?.name === '$' && 
                    ['each', 'map', 'grep'].includes(callee.property?.name)) {
                    if (!this.hasArrayCheck(path)) {
                        vulnerabilities.push({
                            type: 'Unsafe jQuery array operation',
                            line: path.node.loc.start.line,
                            severity: 'MEDIUM'
                        });
                    }
                }
                
                // Check for loose comparisons
                if (path.node.operator === '==' || path.node.operator === '!=') {
                    vulnerabilities.push({
                        type: 'Loose comparison',
                        line: path.node.loc.start.line,
                        severity: 'MEDIUM'
                    });
                }
            },
            
            MemberExpression(path) {
                // Check for __proto__ access
                if (path.node.property.name === '__proto__') {
                    vulnerabilities.push({
                        type: 'Prototype pollution',
                        line: path.node.loc.start.line,
                        severity: 'CRITICAL'
                    });
                }
            }
        });
        
        return vulnerabilities;
    }
}
```

## 3. **Dynamic Analysis Framework**

### 3.1 **Browser-Based Testing**
```javascript
class DynamicTestRunner {
    constructor() {
        this.testResults = [];
        this.monitoredObjects = new Set();
    }
    
    async runTests(testCases) {
        // Monitor prototype pollution
        this.monitorPrototype();
        
        // Monitor type coercions
        this.monitorTypeCoercions();
        
        // Monitor jQuery operations
        this.monitorJQuery();
        
        for (const testCase of testCases) {
            const result = await this.executeTestCase(testCase);
            this.testResults.push(result);
        }
        
        return this.generateReport();
    }
    
    monitorPrototype() {
        const originalDefineProperty = Object.defineProperty;
        Object.defineProperty = function(obj, prop, descriptor) {
            if (prop === '__proto__' || prop === 'constructor') {
                console.warn(`Prototype pollution attempt: ${prop}`);
                this.trackVulnerability('Prototype pollution', new Error().stack);
            }
            return originalDefineProperty.call(this, obj, prop, descriptor);
        };
    }
    
    monitorTypeCoercions() {
        const handlers = {
            get: (target, prop) => {
                if (prop === Symbol.toPrimitive) {
                    console.warn('Symbol.toPrimitive accessed');
                }
                return target[prop];
            }
        };
        
        // Wrap all objects with proxy
        const originalParse = JSON.parse;
        JSON.parse = function(...args) {
            const result = originalParse.apply(this, args);
            return new Proxy(result, handlers);
        };
    }
    
    monitorJQuery() {
        if (window.$) {
            const originalEach = $.each;
            $.each = function(array, callback) {
                if (!Array.isArray(array) && typeof array === 'object') {
                    console.warn('$.each called with non-array:', array);
                    this.trackVulnerability('Type confusion in $.each', array);
                }
                return originalEach.call(this, array, callback);
            };
        }
    }
    
    async executeTestCase(testCase) {
        const startTime = performance.now();
        let error = null;
        let result = null;
        
        try {
            result = await testCase.execute();
        } catch (e) {
            error = e;
        }
        
        const duration = performance.now() - startTime;
        
        return {
            name: testCase.name,
            success: !error,
            error,
            result,
            duration,
            vulnerabilities: this.capturedVulnerabilities
        };
    }
}
```

### 3.2 **Comprehensive Test Suite**
```javascript
class VulnerabilityTestSuite {
    constructor() {
        this.tests = [];
        this.setupTests();
    }
    
    setupTests() {
        // Type Confusion Tests
        this.tests.push({
            name: 'Prototype Pollution via __proto__',
            execute: () => {
                const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
                const target = {};
                Object.assign(target, malicious);
                return target.polluted === true;
            },
            expected: false
        });
        
        this.tests.push({
            name: 'Loose Comparison Bypass',
            execute: () => {
                const auth = JSON.parse('{"isAdmin": "true"}');
                return auth.isAdmin == true; // Should be false with strict
            },
            expected: false
        });
        
        this.tests.push({
            name: 'Array Length DoS',
            execute: () => {
                const startTime = performance.now();
                const data = JSON.parse('{"length": 1000000000}');
                const arr = Array.from(data);
                const duration = performance.now() - startTime;
                return duration > 1000; // Should not take >1s
            },
            expected: false
        });
        
        this.tests.push({
            name: 'NaN Injection',
            execute: () => {
                const data = JSON.parse('{"value": NaN}');
                return isNaN(data.value);
            },
            expected: false
        });
        
        this.tests.push({
            name: 'XSS via jQuery.each',
            execute: () => {
                const malicious = JSON.parse('["<img src=x onerror=alert(1)>"]');
                let html = '';
                $.each(malicious, (i, val) => {
                    html += val;
                });
                return html.includes('<script') || html.includes('onerror');
            },
            expected: false
        });
        
        this.tests.push({
            name: 'Object.is Edge Cases',
            execute: () => {
                const data = JSON.parse('{"value": -0}');
                return Object.is(data.value, 0); // Should be false
            },
            expected: false
        });
        
        this.tests.push({
            name: 'Getter Injection',
            execute: () => {
                const malicious = JSON.parse('{"get value()": "malicious"}');
                return typeof malicious.value === 'function';
            },
            expected: false
        });
        
        this.tests.push({
            name: 'RegExp ReDoS',
            execute: () => {
                const startTime = performance.now();
                const pattern = JSON.parse('{"pattern": "(a+)+$"}');
                const regex = new RegExp(pattern.pattern);
                regex.test('a'.repeat(1000) + '!');
                const duration = performance.now() - startTime;
                return duration > 100; // Should be fast
            },
            expected: false
        });
    }
    
    async run() {
        const results = [];
        for (const test of this.tests) {
            try {
                const result = await test.execute();
                results.push({
                    name: test.name,
                    passed: result === test.expected,
                    actual: result,
                    expected: test.expected
                });
            } catch (error) {
                results.push({
                    name: test.name,
                    passed: false,
                    error: error.message
                });
            }
        }
        return results;
    }
}
```

## 4. **Automated Penetration Testing**

### 4.1 **API Fuzzing Script**
```javascript
class APISecurityTester {
    constructor(baseURL, endpoints) {
        this.baseURL = baseURL;
        this.endpoints = endpoints;
        this.payloads = this.generatePayloads();
    }
    
    generatePayloads() {
        return {
            prototypePollution: [
                '{"__proto__": {"polluted": true}}',
                '{"constructor": {"prototype": {"polluted": true}}}',
                '{"__proto__": {"isAdmin": true}}',
                '{"__proto__": {"toString": "malicious"}}'
            ],
            
            typeConfusion: [
                '{"value": "string"}',
                '{"value": 123}',
                '{"value": true}',
                '{"value": null}',
                '{"value": []}',
                '{"value": {}}',
                '{"value": "123"}',
                '{"value": "true"}',
                '{"value": "null"}',
                '{"value": "undefined"}'
            ],
            
            arrayManipulation: [
                '{"items": []}',
                '{"items": {}}',
                '{"items": {"length": 1000000}}',
                '{"items": {"forEach": "malicious"}}',
                '{"items": [1,2,3]}',
                '{"items": "not an array"}'
            ],
            
            injectionAttacks: [
                '{"callback": "alert(1)"}',
                '{"data": "<script>alert(1)</script>"}',
                '{"regex": "(a+)+$"}',
                '{"pattern": ".*"}',
                '{"query": "1; DROP TABLE users;--"}'
            ],
            
            dosAttacks: [
                '{"data": {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}}',
                '{"array": ' + '['.repeat(10000) + ']' + '}'.repeat(10000),
                '{"string": "' + 'A'.repeat(10000000) + '"}',
                '{"number": 1e1000}'
            ]
        };
    }
    
    async testEndpoint(endpoint) {
        const results = [];
        
        for (const [category, payloads] of Object.entries(this.payloads)) {
            for (const payload of payloads) {
                const result = await this.sendRequest(endpoint, payload);
                results.push({
                    endpoint: endpoint.path,
                    category,
                    payload,
                    status: result.status,
                    responseTime: result.responseTime,
                    vulnerability: this.analyzeResponse(result)
                });
            }
        }
        
        return results;
    }
    
    async sendRequest(endpoint, payload) {
        const startTime = Date.now();
        
        try {
            const response = await fetch(`${this.baseURL}${endpoint.path}`, {
                method: endpoint.method || 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Test-Header': 'security-scan'
                },
                body: payload
            });
            
            const responseTime = Date.now() - startTime;
            const responseBody = await response.text();
            
            return {
                status: response.status,
                responseTime,
                body: responseBody,
                headers: response.headers
            };
        } catch (error) {
            return {
                status: 0,
                responseTime: Date.now() - startTime,
                error: error.message
            };
        }
    }
    
    analyzeResponse(result) {
        const indicators = {
            prototypePollution: result.body.includes('polluted') || 
                               result.body.includes('__proto__'),
            xss: result.body.includes('<script>') || 
                 result.body.includes('alert(') ||
                 result.body.includes('onerror'),
            dos: result.responseTime > 5000 || 
                 result.status === 500,
            injection: result.body.includes('SQL') ||
                       result.body.includes('syntax error')
        };
        
        return Object.entries(indicators).find(([_, detected]) => detected)?.[0] || null;
    }
}
```

## 5. **Continuous Integration Pipeline**

### 5.1 **GitHub Actions Workflow**
```yaml
name: Security Testing Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '16'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run static analysis
      run: |
        npm run lint:security
        npm run scan:ast
    
    - name: Run dynamic tests
      run: |
        npm run test:security
        npm run test:fuzzing
    
    - name: OWASP Dependency Check
      run: |
        npm install -g dependency-check
        dependency-check ./package.json --unused --missing
    
    - name: Snyk Security Scan
      run: |
        npm install -g snyk
        snyk test --severity-threshold=high
    
    - name: Run penetration tests
      run: |
        npm run test:penetration
    
    - name: Generate report
      run: |
        npm run security:report
    
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: ./security-reports/
```

### 5.2 **Pre-commit Hook**
```javascript
// .husky/pre-commit
const execSync = require('child_process').execSync;

function runSecurityChecks() {
    const stagedFiles = execSync('git diff --cached --name-only --diff-filter=ACM')
        .toString()
        .split('\n')
        .filter(f => f.endsWith('.js') || f.endsWith('.json'));
    
    const vulnerabilities = [];
    
    for (const file of stagedFiles) {
        const content = require('fs').readFileSync(file, 'utf8');
        
        // Check for dangerous patterns
        if (content.includes('JSON.parse(') && !content.includes('try')) {
            vulnerabilities.push(`${file}: JSON.parse without try-catch`);
        }
        
        if (content.includes('==') && !content.includes('===')) {
            vulnerabilities.push(`${file}: Loose comparison detected`);
        }
        
        if (content.includes('__proto__')) {
            vulnerabilities.push(`${file}: __proto__ access detected`);
        }
        
        if (content.includes('$.each') && !content.includes('Array.isArray')) {
            vulnerabilities.push(`${file}: $.each without array validation`);
        }
    }
    
    if (vulnerabilities.length > 0) {
        console.error('Security vulnerabilities found:');
        vulnerabilities.forEach(v => console.error(`  - ${v}`));
        process.exit(1);
    }
}

runSecurityChecks();
```

## 6. **Monitoring & Detection**

### 6.1 **Runtime Protection**
```javascript
class RuntimeProtector {
    constructor() {
        this.violations = [];
        this.setupProtections();
    }
    
    setupProtections() {
        this.protectJSONParse();
        this.protectJQueryMethods();
        this.protectObjectOperations();
    }
    
    protectJSONParse() {
        const originalParse = JSON.parse;
        JSON.parse = function(text, reviver) {
            // Size limits
            if (text.length > 1024 * 1024) {
                throw new Error('JSON payload too large');
            }
            
            // Detect nested structures
            let depth = 0;
            for (const char of text) {
                if (char === '{' || char === '[') depth++;
                if (char === '}' || char === ']') depth--;
                if (depth > 100) throw new Error('Too deep nesting');
            }
            
            const result = originalParse.call(this, text, reviver);
            
            // Scan for malicious patterns
            if (result && typeof result === 'object') {
                if ('__proto__' in result) {
                    console.warn('Prototype pollution attempt blocked');
                    delete result.__proto__;
                }
            }
            
            return result;
        };
    }
    
    protectJQueryMethods() {
        if (window.$) {
            const originalEach = $.each;
            $.each = function(collection, callback) {
                if (!Array.isArray(collection) && 
                    typeof collection !== 'function' &&
                    collection !== null) {
                    console.warn('$.each called with suspicious type:', typeof collection);
                    this.violations.push({
                        type: 'JQUERY_TYPE_CONFUSION',
                        collection: collection,
                        stack: new Error().stack
                    });
                }
                return originalEach.call(this, collection, callback);
            };
        }
    }
    
    protectObjectOperations() {
        const handlers = {
            set: (obj, prop, value) => {
                if (prop === '__proto__' || prop === 'constructor') {
                    console.warn(`Blocked ${prop} assignment`);
                    return false;
                }
                obj[prop] = value;
                return true;
            }
        };
        
        // Monitor all new objects
        const originalObject = Object;
        window.Object = new Proxy(originalObject, {
            construct(target, args) {
                const obj = new target(...args);
                return new Proxy(obj, handlers);
            }
        });
    }
}
```

## 7. **Test Execution Matrix**

| Test Category | Tools | Frequency | Severity |
|--------------|-------|-----------|----------|
| Static Analysis | ESLint, AST Scanner | Every commit | High |
| Unit Tests | Jest with security cases | Every PR | Medium |
| Fuzzing | Custom fuzzer | Daily | Critical |
| Penetration Testing | Automated scripts | Weekly | Critical |
| Dependency Scan | Snyk, OWASP | Daily | High |
| Runtime Monitoring | Custom protector | Always | Critical |
| Performance Testing | Load tests | Weekly | Medium |

## 8. **Reporting & Metrics**

```javascript
class SecurityReporter {
    generateReport(results) {
        return {
            timestamp: new Date().toISOString(),
            summary: {
                totalTests: results.length,
                passed: results.filter(r => r.passed).length,
                failed: results.filter(r => !r.passed).length,
                critical: results.filter(r => r.severity === 'CRITICAL' && !r.passed).length,
                high: results.filter(r => r.severity === 'HIGH' && !r.passed).length,
                medium: results.filter(r => r.severity === 'MEDIUM' && !r.passed).length
            },
            vulnerabilities: results.filter(r => !r.passed).map(r => ({
                name: r.name,
                severity: r.severity,
                description: r.description,
                remediation: r.remediation,
                cwe: r.cwe
            })),
            metrics: {
                coverage: this.calculateCoverage(results),
                riskScore: this.calculateRiskScore(results),
                trend: await this.getTrendData()
            }
        };
    }
    
    calculateRiskScore(results) {
        const weights = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1 };
        const failedVulns = results.filter(r => !r.passed);
        
        const totalScore = failedVulns.reduce((score, vuln) => {
            return score + (weights[vuln.severity] || 0);
        }, 0);
        
        return {
            score: totalScore,
            maxPossible: results.length * 10,
            percentage: (totalScore / (results.length * 10)) * 100
        };
    }
}
```

