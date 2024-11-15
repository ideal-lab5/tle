// __mocks__/@polkadot/types.js

class Metadata {
  constructor(registry, hexData) {
    // this.registry = registry;
    // this.hexData = hexData;
  }

  toHex() {
    // return this.hexData;
    return ''
  }
}

class Compact {
  constructor(registry, value) {
    // this.registry = registry;
    // this.value = value;
  }

  // Implement mock methods or properties as needed
}

class TypeRegistry {
  createType(type, value) {
    // Implement mock createType logic or return a simple value
    return value
  }

  register(types) {
    // Implement mock register logic or return a simple value
  }

  setMetadata(metadata) {
    // Implement mock register logic or return a simple value
  }
}

export { Compact, Metadata, TypeRegistry }
