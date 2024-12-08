import logging

from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/openotp/")
async def read_item(request: Request):
    logging.info(await request.body())
    return {"item_id": "", "q": None}
