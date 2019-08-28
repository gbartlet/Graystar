import asyncio
import sqlite3

#Database
#creating a database
sqlite_file = '/Users/farid/Desktop/data2.db'
conn = sqlite3.connect (sqlite_file)
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS GrayStar2 (packet_number INT, src_IP TEXT, src_port INT, dst_ip TEXT, dst_port INT, time TEXT, flag TEXT, len INT)')

async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')
    # c.execute ("INSERT INTO GrayStar VALUES (?,?,?)", (message[0:15], "test1", "test2"))
    # conn.commit()
    # print(f"Received {message!r} from {addr!r}")
    dt = message.split()
    c.execute ("INSERT INTO GrayStar VALUES (?,?,?,?,?,?,?,?)", (dt[0], dt[1], dt[2], dt[3], str(dt[4]) + str(dt[5]) +str(dt[6]), dt[7], dt[8], dt[9]))
    conn.commit()
    writer.write(data)
    await writer.drain()
    writer.close()

async def main():
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
