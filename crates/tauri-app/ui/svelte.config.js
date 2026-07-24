export default {
  onwarn(warning) {
    throw new Error(
      `Svelte compiler warning ${warning.code ?? 'unknown'}: ${warning.message}`
    );
  }
};
