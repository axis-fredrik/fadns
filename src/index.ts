/*
    FADNS

    A Stupid DNS server (no TCP support)

    Little endian platforms supported only.

    Usage with dig:
    dig @localhost www.aftonbladet.se

    usage with nslookup:
    nslookup www.aftonbladet.se localhost
*/

import dgram, {RemoteInfo} from "dgram";

const server = dgram.createSocket('udp4');

let DEFAULT_RESOLVE_IP = [127, 0, 0, 1];

const DNSTable: Record<string, Array<number>> = {
    'www.google.se': [192, 168, 0, 1],
    'www.aftonbladet.se': [13, 13, 17, 208]
}

server.on('error', (err: any) => {
    console.log(`server error:\n${err.stack}`);
    server.close();
});

const ADDRecSize = 12;

enum DnsOpcodeType {
    StandardQuery = 0
}

type TDNSFlags = {
    q: boolean,
    opcode: DnsOpcodeType,
    aa: boolean,
    tc: boolean,
    rd: boolean,
    ra: boolean,
    z: number,
    rcode: number
};

const DNSHeaderSize = 2 * 6;

type TDNSHeader = {
    id: number,
    flags: TDNSFlags,
    qdcount: number,
    ancount: number,
    nscount: number,
    arcount: number
}

type TDNSMessage = {
    qname: string,
    qtype: number,
    qclass: number
}

const DNSFlags = {
    // Kontrollera om detta faktiskt stämmer?
    unpack: (flags: number): TDNSFlags => {
        const tf = flags & 0xffff;
        const tmp = {
            q: !!(tf >> 0 & 0x1),
            opcode: tf >> 1 & 0xf,
            aa: !!(tf >> 5 & 0x1),
            tc: !!(tf >> 6 & 0x1),
            rd: !!(tf >> 7 & 0x1),
            ra: !!(tf >> 8 & 0x1),
            z: tf >> 9 & 0x7,
            rcode: tf >> 12 & 0xf
        };
        return tmp;
    },
    pack: (q: boolean, opcode: number, aa: boolean, tc: boolean, rd: boolean, ra: boolean, z: number, rcode: number): Buffer => {
        const buff = Buffer.alloc(2);
        // High byte
        buff[0] |= (q ? 1 : 0) << 7;
        buff[0] |= (opcode & 0xf) << 3;
        buff[0] |= (aa ? 1 : 0) << 2;
        buff[0] |= (tc ? 1 : 0) << 1;
        buff[0] |= (rd ? 1 : 0);
        buff[1] |= (ra ? 1 : 0) << 7;
        buff[1] |= (z & 0x7) << 4;
        buff[1] |= rcode & 0xf;

        return buff;

    }
}


const DNSHeader = {
    unpack: (buff: Buffer): TDNSHeader => {
        return {
            id: buff[0] << 8 | buff[1],
            flags: DNSFlags.unpack(buff[2] << 8 | buff[3]),
            qdcount: buff[4] << 8 | buff[5],
            ancount: buff[6] << 8 | buff[7],
            nscount: buff[8] << 8 | buff[9],
            arcount: buff[10] << 8 | buff[11],
        };
    },
    pack: (reqH: TDNSHeader, q: Buffer) => {
        return Buffer.concat([
            Pack16(reqH.id),
            DNSFlags.pack(true, 0, true, false, true, true, 0, 0),
            Pack16(1),
            Pack16(1),
            Pack16(0),
            Pack16(0),
            q
        ]);
    }
}


const ParseName = (buffer: Buffer, prefix?: string): string => {
    const len = buffer[0];
    const prf = (prefix || '') + buffer.subarray(1, len + 1);
    const rem = buffer.subarray(len + 1, buffer.length);
    if (rem.length > 1)
        return ParseName(rem, prf.toString() + '.');
    return prf || '';
}


const PackName = (cname: string): Buffer => {
    const result: Array<Buffer> = [];
    const parts = cname.split('.');
    parts.forEach((part) => {
        const subBuff = Buffer.alloc(part.length + 1);
        subBuff[0] = part.length;
        for (let i = 0; i < part.length; i++) {
            subBuff[i + 1] = part.charCodeAt(i);
        }
        result.push(subBuff);
    })
    const stop = Buffer.alloc(1);
    stop[0] = 0;

    result.push(stop);

    return Buffer.concat(result);
}

const DNSMessage = {
    unpack: (buff: Buffer): TDNSMessage => {
        const qname = buff.subarray(0, buff.length - 5);
        return {
            qname: ParseName(qname),
            qtype: buff[buff.length - 4] << 8 | buff[buff.length - 3],
            qclass: buff[buff.length - 2] << 8 | buff[buff.length - 1]
        }
    }
}

const Pack16 = (value: number) => {
    const buff = Buffer.alloc(2);
    buff[0] = value >> 8 & 0xff;
    buff[1] = value & 0xff;
    return buff;
}

const Pack32 = (value: number) => {
    const buff = Buffer.alloc(4);
    buff[0] = value >> 24 & 0xff;
    buff[1] = value >> 16 & 0xff;
    buff[2] = value >> 8 & 0xff;
    buff[3] = value & 0xff;
    return buff;
}

const ARecordResponse = (cname: string, ip: Array<number>): Buffer => {
    const ARecord = [
        PackName(cname),
        Pack16(0x1),   // Record type
        Pack16(0x1),   // Class
        Pack32(600), // TTL
        Pack16(4), // RD Length
        Buffer.from(ip),
    ]

    return Buffer.concat(ARecord);
}

server.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
    const rawHeader = msg.subarray(0, DNSHeaderSize);
    const dnsHeader = DNSHeader.unpack(rawHeader);
    const messageBody = msg.subarray(DNSHeaderSize, msg.length - (ADDRecSize * dnsHeader.arcount) + 1);

    switch (dnsHeader.flags.opcode) {
        case DnsOpcodeType.StandardQuery:
            const reply = [];
            for(let i=0; i<dnsHeader.qdcount; i++) {
                const message = DNSMessage.unpack(messageBody.subarray(0, messageBody.length));
                if (!DNSTable[message.qname]) {
                    reply.push(ARecordResponse(message.qname, DEFAULT_RESOLVE_IP));
                } else {
                    reply.push(ARecordResponse(message.qname, DNSTable[message.qname]));
                }
            }
            const replyMsg = Buffer.concat([DNSHeader.pack(dnsHeader, messageBody), Buffer.concat(reply)])
            server.send(replyMsg, rinfo.port, rinfo.address);
            break;
        default:
            console.log('UNKNOWN DNS OPCODE', dnsHeader.flags.opcode);
            break;
    }
});

server.on('listening', () => {
    const address = server.address();
    console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(53);