
CXX = g++
CXXFLAGS = -lpcap

# 타겟과 소스 파일 설정
TARGET = csa-attack
SRC = csa-attack.cpp

# 기본 타겟
all: $(TARGET)

# 타겟 빌드 규칙
$(TARGET): $(SRC)
	$(CXX) $(SRC) -o $(TARGET) $(CXXFLAGS)

# 클린업 규칙
clean:
	rm -f $(TARGET)
