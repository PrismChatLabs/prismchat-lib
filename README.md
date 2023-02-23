# Prism Lib

This is the main client library for the prism encryption scheme.

## Compile

``` bash
npm run build
```

## Test

``` bash
npm run test
```

## Publish

1. Commit all code and merge up to master.
2. Run prepublish script to run tests and test a build.
3. Update version in ```package.json```.
4. Publish to NPM.

``` bash
npm run prepublish
npm publish
```
