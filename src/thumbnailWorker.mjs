import { encodeThumbnail, probeThumbnailSupport } from './thumbnail.mjs'

const input = process.argv[2]
const result = input ? await encodeThumbnail(JSON.parse(input)) : JSON.stringify(await probeThumbnailSupport())
if (result) process.stdout.write(result)
