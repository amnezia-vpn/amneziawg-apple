# [WireGuard](https://www.wireguard.com/) SPM


## WireGuardKit integration via Swift Package Manager

1. Open your Xcode project and add the Swift package with the following URL:

   ```
   https://github.com/StarProxima/amneziawg-apple
   ```

2. WireGuardFoundation будет автоматически загружен из релизов GitHub.

## WireGuardFoundation Update Process

Для обновления WireGuardFoundation следуйте этим шагам:

1. Перейдите в директорию `Sources/WireGuardFoundation/`:

   ```bash
   cd Sources/WireGuardFoundation/
   ```

2. Очистите предыдущую сборку:

   ```bash
   make clean
   ```

3. Соберите новый XCFramework:

   ```bash
   make build-xcframework
   ```

4. Получите checksum архива:

   checksum можно увидеть в конце вывода `make build-xcframework`
   
   

   Пример вывода:
   ```
   b546dc09726f18ea8a59f3c8c3df94825694ff3d5163c477a9f381328f8059c5
   ```

5. Скачайте готовый ZIP-файл из директории `.build/` и либо:
   - Загрузите его как релиз на GitHub (например, версия 1.0.0)
   - Или используйте локально в Package.swift

### Примеры использования

**Локальная установка в Package.swift:**
```swift
.binaryTarget(
    name: "WireGuardFoundation",
    path: "Sources/WireGuardFoundation/.build/WireGuardFoundation.xcframework"
)
```

**Удаленная установка из GitHub релиза:**
```swift
.binaryTarget(
    name: "WireGuardFoundation",
    url: "https://github.com/StarProxima/amneziawg-apple/releases/download/1.0.0/WireGuardFoundation.xcframework.zip",
    checksum: "b546dc09726f18ea8a59f3c8c3df94825694ff3d5163c477a9f381328f8059c5"
)
```

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
