const path = require('path')
const HtmlWebpackPlugin = require('html-webpack-plugin')

module.exports = ({ mode } = { mode: 'production' }) => {
  console.log(`mode is: ${mode}`)

  return {
    mode,
    entry: './src/index.js',
    resolve: {
      fullySpecified: false,
    },
    test: /\.m?js/, // fix:issue: https://github.com/webpack/webpack/issues/11467
    output: {
      publicPath: '/',
      path: path.resolve(__dirname, 'build'),
      filename: 'bundled.js',
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './public/index.html',
      }),
    ],
  }
}
