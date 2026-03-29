# Upgrade Plan: MegaBasterd (20260329151302)

- **Generated**: 2026-03-29 15:13
- **HEAD Branch**: master
- **HEAD Commit ID**: 6df2c8aeb8062bd2792173a6772e891f08cbca00

## Available Tools

**JDKs**
- JDK 21.0.3: `C:\Programs\Java 21 JDK\bin` (target JDK, used by steps 2-7)

**Build Tools**
- Maven: **TO_BE_INSTALLED** 3.9.9 (no Maven installation found; required by all build steps; install in step 1)

## Guidelines

> Note: You can add any specific guidelines or constraints for the upgrade process here if needed, bullet points are preferred.

## Options

- Working branch: appmod/java-upgrade-20260329151302
- Run tests before and after the upgrade: true

## Upgrade Goals

- Upgrade Java from 8 to 21

### Technology Stack

| Technology/Dependency | Current | Min Compatible | Why Incompatible |
| --------------------- | ------- | -------------- | ---------------- |
| Java | 8 (source/target 1.8) | 21 | User requested |
| Maven | not installed | 3.9.0 | No Maven present; 3.9+ required for Java 21 |
| maven-compiler-plugin | (unversioned, default) | 3.11.0 | Must be pinned >= 3.11 to compile Java 21 bytecode |
| maven-surefire-plugin | (unversioned, default) | 3.1.0 | Should be pinned >= 3.1.0 for Java 17+ module system |
| javax.xml.bind:jaxb-api EOL | 2.3.1 | N/A | Removed from JDK 9+; 2 usages in MiscTools.java (DatatypeConverter, HexBinaryAdapter) - replace with java.util.HexFormat |
| xuggle-xuggler-server-all EOL | 5.7.0-SNAPSHOT | N/A | Abandoned ~2013; native JNI incompatible with Java 21; replace with org.bytedeco:javacv-platform:1.5.10 |
| webp-imageio-sejda EOL | 0.1.0 | N/A | Abandoned 2014; native JNI; replace with com.twelvemonkeys.imageio:imageio-webp:3.10.1 |
| commons-io | 2.14.0 | 2.14.0 | - |
| sqlite-jdbc | 3.43.0.0 | 3.43.0.0 | - |
| jackson-core / databind / annotations | 2.15.3 | 2.15.3 | - |
| commons-collections4 | 4.4 | 4.4 | - |

### Derived Upgrades

- Install Maven 3.9.9 (no Maven present; 3.9+ required for Java 21)
- Pin maven-compiler-plugin to 3.13.0 with release=21 (compile Java 21 bytecode)
- Pin maven-surefire-plugin to 3.3.1 (Java 17+ compatibility)
- Remove javax.xml.bind:jaxb-api; migrate 2 usages in MiscTools.java to java.util.HexFormat
- Replace xuggle-xuggler-server-all with org.bytedeco:javacv-platform:1.5.10; rewrite Thumbnailer video thumbnail using FFmpegFrameGrabber
- Replace webp-imageio-sejda:0.1.0 with com.twelvemonkeys.imageio:imageio-webp:3.10.1

## Upgrade Steps

- **Step 1: Setup Environment**
  - **Rationale**: Maven is not installed. All subsequent build steps require Maven 3.9+ (compatible with Java 21).
  - **Changes to Make**:
    - [ ] Install Maven 3.9.9 via appmod-install-maven tool
    - [ ] Confirm Maven binary path returned by tool
  - **Verification**:
    - Command: appmod-list-mavens to confirm installation
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Maven 3.9.9 available

---

- **Step 2: Setup Baseline**
  - **Rationale**: Establish pre-upgrade compile/test results. Project has no real unit tests (placeholder file only).
  - **Changes to Make**:
    - [ ] Run baseline compilation with current pom.xml settings (Java 8 source/target, Java 21 JDK)
    - [ ] Document PASS/FAIL (expected: compile may fail due to xuggle SNAPSHOT download or javax.xml.bind issues)
  - **Verification**:
    - Command: mvn clean test-compile then mvn clean test
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Document results as baseline

---

- **Step 3: Replace EOL Libraries (xuggle -> JavaCV, webp-imageio-sejda -> TwelveMonkeys)**
  - **Rationale**: Both libraries are abandoned with native JNI incompatible with Java 21. High-risk step handled early.
  - **Changes to Make**:
    - [ ] In pom.xml: remove xuggle repository block and xuggle-xuggler-server-all dependency; add org.bytedeco:javacv-platform:1.5.10
    - [ ] In pom.xml: replace webp-imageio-sejda:0.1.0 with com.twelvemonkeys.imageio:imageio-webp:3.10.1 and imageio-core:3.10.1
    - [ ] Rewrite Thumbnailer.java: replace all xuggler imports and createVideoThumbnail() with FFmpegFrameGrabber implementation
  - **Verification**:
    - Command: mvn clean test-compile -q
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Compilation SUCCESS

---

- **Step 4: Upgrade Java Build Configuration to 21**
  - **Rationale**: Update compiler source/target from 1.8 to 21 and pin compatible plugin versions.
  - **Changes to Make**:
    - [ ] In pom.xml: change maven.compiler.source and maven.compiler.target from 1.8 to 21
    - [ ] Add maven-compiler-plugin:3.13.0 with release=21 to build/plugins
    - [ ] Add maven-surefire-plugin:3.3.1 to build/plugins
  - **Verification**:
    - Command: mvn clean test-compile -q
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Compilation SUCCESS with Java 21 bytecode

---

- **Step 5: Migrate javax.xml.bind to java.util.HexFormat**
  - **Rationale**: javax.xml.bind was removed from JDK 9+. With compiler target now at 21, these usages must be eliminated.
  - **Changes to Make**:
    - [ ] In MiscTools.java: remove javax.xml.bind imports; replace HexBinaryAdapter().marshal(...) with HexFormat.of().formatHex(...)
    - [ ] In MiscTools.java: replace DatatypeConverter.parseHexBinary(s) with HexFormat.of().parseHex(s)
    - [ ] In pom.xml: remove javax.xml.bind:jaxb-api:2.3.1 dependency
  - **Verification**:
    - Command: mvn clean test-compile -q
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Compilation SUCCESS with no javax.xml.bind references

---

- **Step 6: Final Validation**
  - **Rationale**: Verify all upgrade goals met; run full test suite with Java 21.
  - **Changes to Make**:
    - [ ] Verify pom.xml has maven.compiler.source/target=21 and no xuggle/jaxb-api deps
    - [ ] Resolve any remaining TODOs or compile warnings
    - [ ] Clean rebuild and run full test suite
    - [ ] Fix any compilation errors or test failures (iterative loop until 100% pass)
  - **Verification**:
    - Command: mvn clean test
    - JDK: C:\Programs\Java 21 JDK\bin
    - Expected: Compilation SUCCESS + 100% tests pass

## Key Challenges

- **xuggle-xuggler-server-all Replacement**
  - **Challenge**: Xuggler is abandoned since ~2013; uses JNI native libs and internal JDK APIs restricted in Java 21; distributed as SNAPSHOT from a 3rd-party repo.
  - **Strategy**: Replace with org.bytedeco:javacv-platform:1.5.10 (actively maintained FFmpeg Java bindings). Rewrite createVideoThumbnail() in Thumbnailer.java using FFmpegFrameGrabber / Java2DFrameConverter. Public interface of Thumbnailer is preserved.

- **javax.xml.bind Removal**
  - **Challenge**: 2 usages in MiscTools.java rely on classes removed from JDK in Java 9+.
  - **Strategy**: Replace both with java.util.HexFormat (Java 17+). HexFormat.of().parseHex() and HexFormat.of().formatHex() are exact drop-in replacements with no functional difference.

- **No Unit Tests**
  - **Challenge**: The test directory contains only a placeholder text file; test pass rate baseline = 100% (0/0 tests).
  - **Strategy**: Baseline and final validation both confirm compilation + trivial test pass. CVE scan provided as post-upgrade next step.

## Plan Review

All steps are necessary and ordered by risk. No intermediate Java version is needed since JDK 21 is already installed and this is a standalone Swing desktop app (no Spring Boot, no Jakarta migration). Only two source-level incompatibilities exist (both straightforward replacements).

Known limitation: javacv-platform:1.5.10 bundles FFmpeg native binaries for all platforms. This is consistent with how xuggler worked previously and is required for the fat-JAR build.
