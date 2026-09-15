export class RequestSequence {
  constructor() {
    this.value = 0;
  }

  next() {
    this.value += 1;
    return this.value;
  }

  invalidate() {
    this.value += 1;
  }

  isCurrent(request) {
    return request === this.value;
  }
}
