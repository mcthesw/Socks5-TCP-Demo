// 协议细节参考：https://zh.wikipedia.org/wiki/SOCKS#SOCKS5
// 各个阶段的客户端请求和服务端响应格式可以从上面的链接获取

use simple_logger::SimpleLogger;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use log::{error, info};

// Socks5 命令
#[allow(unused)]
#[derive(Debug, PartialEq)]
enum Socks5Command {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

// Socks5 地址类型
#[allow(unused)]
#[derive(Debug, PartialEq)]
enum Socks5AddressType {
    IPv4 = 1,
    Domain = 3,
    IPv6 = 4,
}

// Socks5 请求
#[derive(Debug)]
#[allow(unused)]
struct Socks5Request {
    version: u8,
    command: Socks5Command,
    address_type: Socks5AddressType,
    address: String,
    port: u16,
}

// 用户名和密码
const USERNAME: &str = "user";
const PASSWORD: &str = "pass";

// 自定义错误类型
#[allow(unused)]
#[derive(Debug)]
enum Socks5Error {
    InvalidProtocol,
    UnsupportedCommand,
    UnsupportedAddressType,
    AuthFailed,
    ConnectionFailed,
    IOError(std::io::Error),
}

impl From<std::io::Error> for Socks5Error {
    fn from(err: std::io::Error) -> Self {
        Socks5Error::IOError(err)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化Log
    SimpleLogger::new().init()?;
    info!("Socks5 服务端启动中");

    let listener = TcpListener::bind("127.0.0.1:123").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                error!("接受客户端请求时发生错误: {:?}", e);
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream) -> Result<(), Socks5Error> {
    // Socks5握手阶段
    info!(
        "客户端连接: {:?} 进入Socks5握手阶段",
        stream.peer_addr().unwrap()
    );
    let mut buf = [0; 256];
    stream.read_exact(&mut buf[..2]).await?;
    let ver = buf[0];
    let nmethods = buf[1];
    info!("Socks5 握手版本: {}, 方法数量: {}", ver, nmethods);
    stream.read_exact(&mut buf[..nmethods as usize]).await?;

    // 题目要求身份认证，因此此处只接受包含方法0x02的请求
    if !buf[1..nmethods as usize].contains(&0x02) {
        stream.write_all(&[5, 255]).await?; // (Ver,Method)，服务端返回版本5，并向客户端说明无可接受的方法
        error!("客户端不支持身份认证方法");
        return Err(Socks5Error::InvalidProtocol);
    }

    stream.write_all(&[5, 2]).await?; // 服务端返回版本5，并选择方法0x02（身份认证）
    info!("Socks5握手阶段完成");

    // 用户名密码验证阶段
    info!(
        "客户端连接: {:?} 进入用户名密码验证阶段",
        stream.peer_addr().unwrap()
    );
    stream.read_exact(&mut buf[..2]).await?; // 读出版本号和ulen
    let ulen = buf[1] as usize;
    stream.read_exact(&mut buf[..ulen]).await?; // 读出用户名
    let username = String::from_utf8_lossy(&buf[..ulen]).to_string();

    stream.read_exact(&mut buf[..1]).await?; // 读出plen
    let plen = buf[0] as usize;
    stream.read_exact(&mut buf[..plen]).await?;
    let password = String::from_utf8_lossy(&buf[..plen]).to_string();

    if username != USERNAME || password != PASSWORD {
        info!(
            "用户名：{}，密码：{}\n预期用户名：{}，预期密码:{}",
            username, password, USERNAME, PASSWORD
        );
        stream.write_all(&[5, 1]).await?; // (Ver,Status)，其中Status为0x00表示认证成功，其余表示失败
        error!("用户名密码验证失败");
        return Err(Socks5Error::AuthFailed);
    }
    stream.write_all(&[5, 0]).await?;
    info!("Socks5用户名密码验证成功");

    // 解析请求阶段
    info!(
        "客户端连接: {:?} 进入请求解析阶段",
        stream.peer_addr().unwrap()
    );
    let request = parse_request(&mut stream).await?;
    info!("请求解析完成，结果为: {:?}", request);

    // 连接到目标服务器
    info!(
        "客户端连接: {:?} 进入目标服务器连接阶段",
        stream.peer_addr().unwrap()
    );
    let mut target_stream = match connect_to_target(&request).await {
        Ok(s) => s,
        Err(_) => {
            send_response(&mut stream, 5, &"0.0.0.0".parse().unwrap(), 0).await?;
            return Err(Socks5Error::ConnectionFailed);
        }
    };

    // 发送来自目标服务器的响应
    send_response(&mut stream, 0, &"127.0.0.1".parse().unwrap(), 0).await?;
    info!("目标服务器连接成功");

    // 转发后续数据
    info!(
        "客户端连接: {:?} 进入数据转发阶段",
        stream.peer_addr().unwrap()
    );
    let (mut client_read, mut client_write) = stream.split();
    let (mut target_read, mut target_write) = target_stream.split();

    let client_to_target = async { tokio::io::copy(&mut client_read, &mut target_write).await };
    let target_to_client = async { tokio::io::copy(&mut target_read, &mut client_write).await };

    tokio::try_join!(client_to_target, target_to_client)?;
    info!("数据转发完成，关闭连接");

    Ok(())
}

async fn parse_request(stream: &mut TcpStream) -> Result<Socks5Request, Socks5Error> {
    let mut buf = [0; 260];
    stream.read_exact(&mut buf[..4]).await?; // 前四个字节分别是 VER,CMD,RSV,ATYP
    let command = match buf[1] {
        1 => Socks5Command::Connect,
        2 => Socks5Command::Bind,
        // 暂不支持UDP
        // 3=> Socks5Command::UdpAssociate,
        _ => return Err(Socks5Error::UnsupportedCommand),
    };
    let address_type = match buf[3] {
        1 => Socks5AddressType::IPv4,
        // 暂时只实现IPv4
        // 3 => Socks5AddressType::Domain,
        // 4 => Socks5AddressType::IPv6,
        _ => return Err(Socks5Error::UnsupportedAddressType),
    };

    let address;
    match address_type {
        Socks5AddressType::IPv4 => {
            stream.read_exact(&mut buf[..4]).await?; // IPv4地址长度为4字节
            address = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
        }
        Socks5AddressType::Domain => {
            let len = stream.read_u8().await? as usize;
            stream.read_exact(&mut buf[..len]).await?;
            address = String::from_utf8_lossy(&buf[..len]).to_string();
        }
        Socks5AddressType::IPv6 => {
            stream.read_exact(&mut buf[..16]).await?; // IPv6地址长度为16字节
            address = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]])
            );
        }
    };
    let port = stream.read_u16().await?;
    Ok(Socks5Request {
        version: buf[0],
        command,
        address_type,
        address,
        port,
    })
}

async fn connect_to_target(request: &Socks5Request) -> Result<TcpStream, Socks5Error> {
    let addr = format!("{}:{}", request.address, request.port);
    TcpStream::connect(addr)
        .await
        .map_err(|_| Socks5Error::ConnectionFailed)
}

async fn send_response(
    stream: &mut TcpStream,
    reply: u8,
    bind_addr: &std::net::Ipv4Addr,
    bind_port: u16,
) -> Result<(), Socks5Error> {
    // VER,REP,RSV,ATYP
    stream.write_all(&[5, reply, 0, 1]).await?;
    // BND.ADDR,BND.PORT
    // BND.ADDR,BND.PORT指的是Socks5服务器的IP和端口
    stream.write_all(&bind_addr.octets()).await?;
    stream.write_u16(bind_port).await?;
    Ok(())
}
