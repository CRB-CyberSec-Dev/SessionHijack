# Session Hijacking Project

This repository contains a session hijacking demonstration with two main components: a client-side program and a server-side program.

## Demo video link how this work

https://youtu.be/BpePsMg71UY


## Features

- **Decryption**: The client-side application decrypts cookies from browsers.
- **Decrypted Cookies Sharing**: The decrypted cookies are then shared with the server.
- **Authentication**: Uses JWT tokens with asymmetric key cryptography for secure authentication.
- **Traffic Management**: Prevents socket overflowing traffic.
- **JWT Token Usage**: Ensures secure communication between client and server.

## Requirements

- C++ Compiler (e.g., MSVC for Windows, MS Visual Studio)
- `vcpkg` for managing dependencies
- Libraries: `Boost`, `SQLite3`, `OpenSSL`, `jwt-cpp`, `nlohmann/json`, `libarchive`, `libzip`

## Setup Instructions

### Setting up `vcpkg`

1. Clone the `vcpkg` repository:
    ```
    git clone https://github.com/microsoft/vcpkg.git
    ```

2. Bootstrap `vcpkg`:
    ```
    bootstrap-vcpkg.bat
    ```

3. Integrate `vcpkg` with your build system:
    ```
    vcpkg integrate install
    ```

4. Install the required packages:
    ```
    vcpkg install boost-asio boost-system sqlite3 openssl jwt-cpp nlohmann-json libarchive libzip
    ```

### Building the Project

#### Client-Side

1. Ensure you have the dependencies installed via `vcpkg`.
2. Open the client project in Visual Studio.
3. Configure the following settings in Visual Studio:
    - **Linker > General**: Additional Library Directories
      ```
      ..\vcpkg_installed\x64-windows\lib
      ```
    - **Linker > Input**: Additional Dependencies
      ```
      $(CoreLibraryDependencies);%(AdditionalDependencies);zip.lib;boost_system-vc140-mt.lib;libssl.lib;libcrypto.lib;sqlite3.lib;archive.lib;zstd.lib
      ```
    - **C/C++ > General**: Additional Include Directories
      ```
      ..\vcpkg_installed\x64-windows\include;%(AdditionalIncludeDirectories)
      ```
4. Build the project.

#### Server-Side

1. Ensure you have the dependencies installed via `vcpkg`.
2. Open the server project in Visual Studio.
3. Configure the following settings in Visual Studio:
    - **Linker > General**: Additional Library Directories
      ```
      ..\vcpkg_installed\x64-windows\lib
      ```
    - **Linker > Input**: Additional Dependencies
      ```
      $(CoreLibraryDependencies);%(AdditionalDependencies);zip.lib;boost_system-vc140-mt.lib;libssl.lib;libcrypto.lib;sqlite3.lib;archive.lib;zstd.lib
      ```
    - **C/C++ > General**: Additional Include Directories
      ```
      ..\vcpkg_installed\x64-windows\include;%(AdditionalIncludeDirectories)
      ```
4. Build the project.

## Usage

### Running the Client

The client performs several functions including checking for administrative privileges, managing browser processes, decrypting cookies, and sending them to the server.

### Running the Server

The server receives the decrypted cookies and performs necessary authentication using JWT tokens.

## Code Overview

### Client-Side

The client code handles:
- Checking administrative privileges.
- Managing browser processes.
- Decrypting cookies from browsers.
- Saving cookies to CSV and text files.
- Sending decrypted cookies to the server using a secure connection.
- Verifying JWT tokens for secure communication.

### Server-Side

The server code handles:
- Receiving data from the client.
- Authenticating the client using JWT tokens.

## Security Considerations

- **Decryption**: Uses OpenSSL for secure decryption of browser cookies.
- **JWT Authentication**: Ensures that the client is authenticated using RSA keys.
- **Traffic Management**: Uses Boost.Asio to manage network traffic efficiently and prevent socket overflow.

### Decrypting Cookies

This project includes functionality to decrypt cookies (`encrypted_value`) from Chrome/Chromium 80+ browsers. This works with the latest versions of Edge, Brave, and Chrome as of the date (June 20, 2024). For the decryption method, credit goes to [Georgy Tarasov](https://stackoverflow.com/users/2789641/georgy-tarasov) and the solution provided in [this StackOverflow thread](https://stackoverflow.com/questions/71718371/decrypt-cookies-encrypted-value-from-chrome-chromium-80-in-c-sharp-issue-wi).

## Preventing Socket Overflow

To prevent socket overflowing traffic, the application uses asynchronous I/O operations provided by Boost.Asio. This ensures that the system can handle a large number of connections and data transfers efficiently.

## Contributing

Feel free to contribute to this project by submitting issues or pull requests. Ensure that any new features or bug fixes come with appropriate tests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Buy me a coffee...........!

**BTC :- bc1q90c30lrgcclsd9pmyqpxjecyphg7y0f2grf74u**

<a href="#" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>
