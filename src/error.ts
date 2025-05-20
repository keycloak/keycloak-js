export class NetworkError extends Error {
  readonly response: Response;
  constructor(message: string, options: { response: Response }) {
    super(message);
    this.response = options.response;
  }
}
