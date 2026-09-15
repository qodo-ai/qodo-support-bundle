export class RequestSequence {
  constructor() {
    this.value = 0;
    this.controller = null;
  }

  next() {
    this.controller?.abort();
    this.value += 1;
    this.controller = new AbortController();
    return {
      value: this.value,
      signal: this.controller.signal,
    };
  }

  invalidate() {
    this.controller?.abort();
    this.controller = null;
    this.value += 1;
  }

  isCurrent(request) {
    return request.value === this.value;
  }

  finish(request) {
    if (this.isCurrent(request)) {
      this.controller = null;
    }
  }
}
