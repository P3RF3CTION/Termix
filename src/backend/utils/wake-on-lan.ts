import dgram from "dgram";

const MAC_REGEX = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseMac(mac: string): Buffer {
  return Buffer.from(mac.replace(/[:-]/g, ""), "hex");
}

export function buildMagicPacket(mac: string): Buffer {
  const macBytes = parseMac(mac);
  const packet = Buffer.alloc(102);
  packet.fill(0xff, 0, 6);
  for (let i = 0; i < 16; i++) {
    macBytes.copy(packet, 6 + i * 6);
  }
  return packet;
}

export function isValidMac(mac: string): boolean {
  return MAC_REGEX.test(mac);
}

// Wake-on-LAN magic packets are intended for the local broadcast domain. We
// therefore only permit the limited broadcast address, RFC1918 private
// ranges (typical LAN broadcast addresses), link-local, and IPv4 multicast.
// This prevents the Termix server from being used as a generic UDP relay to
// arbitrary internet or metadata addresses.
export function isValidWolBroadcastAddress(address: string): boolean {
  if (!address) return false;
  const match = IPV4_REGEX.exec(address);
  if (!match) return false;
  const [a, b, c, d] = match.slice(1, 5).map((n) => Number(n));
  if ([a, b, c, d].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  if (a === 255 && b === 255 && c === 255 && d === 255) return true; // limited broadcast
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224 && a <= 239) return true; // multicast
  return false;
}

export function sendWakeOnLan(
  mac: string,
  broadcastAddress = "255.255.255.255",
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!isValidMac(mac)) {
      return reject(new Error("Invalid MAC address"));
    }
    if (!isValidWolBroadcastAddress(broadcastAddress)) {
      return reject(
        new Error(
          "Invalid WOL broadcast address (must be a local broadcast, private, link-local, or multicast IPv4 address)",
        ),
      );
    }

    const packet = buildMagicPacket(mac);
    const socket = dgram.createSocket("udp4");

    socket.once("error", (err) => {
      socket.close();
      reject(err);
    });

    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(packet, 0, packet.length, 9, broadcastAddress, (err) => {
        socket.close();
        if (err) reject(err);
        else resolve();
      });
    });
  });
}
