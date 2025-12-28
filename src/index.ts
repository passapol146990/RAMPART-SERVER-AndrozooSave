import { Hono } from 'hono'
import conn from './db/mongo'

const app = new Hono()

app.get('/', async (c) => {
  try {
    if (conn.readyState !== 1) {
      await new Promise((resolve) => conn.once('connected', resolve));
    }

    const count = await conn.db!.collection("csv").countDocuments();
    console.log("Total CVS documents:", count);
    return c.json({
      message: 'Connected to androzoo database',
      collection: 'cvs',
      totalDocuments: count
    });
  } catch (err) {
    console.error("Error counting CVS documents:", err);
    return c.json({ error: "Failed to count documents", details: err }, 500);
  }
})

export default app
