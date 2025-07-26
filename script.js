
    // Simplified signaling stub
    
    // const ws = new WebSocket('wss://your-signaling-server');
    // ws.onmessage = (e) => {
    //   const data = JSON.parse(e.data);
    //   if (data.type === 'offer') {
    //     peerConnections[data.sender].setRemoteDescription(new RTCSessionDescription(data.description));
    //   } else if (data.type === 'answer') {
    //     peerConnections[data.sender].setRemoteDescription(new RTCSessionDescription(data.answer));
    //   } else if (data.type === 'candidate') {
    //     peerConnections[data.sender].addIceCandidate(new RTCIceCandidate(data.candidate));
    //   } else if (data.type === 'ipCheck') {
    //     // Compare IPs
    //   } else if (data.type === 'pinValidation') {
    //     if (data.valid) {
    //       // Proceed
    //     } else {
    //       updateStatus('Invalid PIN.', true);
    //     }
    //   } else if (data.type === 'resumeRequest') {
    //     // Send resume metadata
    //   }
    // };
    // ws.send(JSON.stringify({ type: 'pinValidation', pin: sessionPin.value, sessionId }));
    

    let peerConnections = {};
    let dataChannels = {};
    let sessionId = localStorage.getItem('sessionId') || Math.random().toString(36).substring(2, 10);
    localStorage.setItem('sessionId', sessionId);
    let sessionPinValue = localStorage.getItem('sessionPin') || Math.random().toString(36).substring(2, 6);
    const sessionPin = document.getElementById('sessionPin');
    sessionPin.value = sessionPinValue;
    let selectedFiles = [];
    let transferCancelled = false;
    let transferStartTime = 0;
    let transferredBytes = 0;
    let sessionTimeout;
    let transferStats = { filesSent: 0, totalBytes: 0, speeds: [] };
    let resumeState = {};
    const statusDiv = document.getElementById('status');
    const connectionStatusDiv = document.getElementById('connectionStatus');
    const bandwidthDiv = document.getElementById('bandwidth');
    const analyticsDiv = document.getElementById('analytics');
    const checksumStatusDiv = document.getElementById('checksumStatus');
    const debugPanel = document.getElementById('debugPanel');
    const fileInput = document.getElementById('fileInput');
    const sizeLimitInput = document.getElementById('sizeLimit');
    const compressionLevel = document.getElementById('compressionLevel');
    const previewTableBody = document.getElementById('previewTableBody');
    const fileList = document.getElementById('fileList');
    const transferHistory = document.getElementById('transferHistory');
    const progressBar = document.getElementById('progress');
    const cancelButton = document.getElementById('cancelButton');
    const spinner = document.getElementById('spinner');

    // Valid file types
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif',
      'video/mp4', 'video/webm',
      'audio/mpeg', 'audio/wav',
      'application/zip', 'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

    // Escape HTML to prevent injection
    function escapeHTML(str) {
      return (str || '').replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/`/g, '&#96;')
        .replace(/\$/g, '&#36;')
        .replace(/{/g, '&#123;')
        .replace(/}/g, '&#125;');
    }

    // Log debug message
    function logDebug(message, error = null) {
      try {
        const log = document.createElement('div');
        const timestamp = new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });
        log.textContent = '[' + timestamp + '] ' + escapeHTML(message);
        log.className = error ? 'error' : 'success';
        debugPanel.appendChild(log);
        console.log('[' + timestamp + '] ' + message, error || '');
      } catch (err) {
        console.error('Debug logging failed:', err);
      }
    }

    // Update status
    function updateStatus(message, isError = false) {
      try {
        statusDiv.textContent = escapeHTML(message);
        statusDiv.className = isError ? 'error' : 'success';
        logTransfer(message, isError);
        logDebug('Status updated: ' + message, isError ? new Error(message) : null);
        if (Notification.permission === 'granted') {
          new Notification('File Sharing App', { body: message });
        }
      } catch (err) {
        logDebug('Error updating status: ' + err.message, err);
      }
    }

    // Update checksum status
    function updateChecksumStatus(message, isError = false) {
      try {
        checksumStatusDiv.textContent = escapeHTML(message);
        checksumStatusDiv.className = isError ? 'error' : 'success';
        logTransfer(message, isError);
        logDebug('Checksum status updated: ' + message, isError ? new Error(message) : null);
      } catch (err) {
        logDebug('Error updating checksum status: ' + err.message, err);
      }
    }

    // Update connection status
    function updateConnectionStatus(message) {
      try {
        connectionStatusDiv.textContent = 'Connection: ' + escapeHTML(message);
        logDebug('Connection status updated: ' + message);
      } catch (err) {
        logDebug('Error updating connection status: ' + err.message, err);
      }
    }

    // Update bandwidth
    function updateBandwidth(bytes, startTime) {
      try {
        const elapsed = (performance.now() - startTime) / 1000;
        const speedMbps = elapsed > 0 ? (bytes * 8 / elapsed / 1e6).toFixed(2) : 0;
        bandwidthDiv.textContent = 'Bandwidth: ' + speedMbps + ' Mbps';
        if (speedMbps > 0 && speedMbps < 1) {
          updateStatus('Warning: Slow connection detected.', true);
        }
        transferStats.speeds.push(parseFloat(speedMbps));
        logDebug('Bandwidth updated: ' + speedMbps + ' Mbps');
      } catch (err) {
        logDebug('Error updating bandwidth: ' + err.message, err);
      }
    }

    // Update analytics
    function updateAnalytics() {
      try {
        const avgSpeed = transferStats.speeds.length > 0 ?
          (transferStats.speeds.reduce((a, b) => a + b, 0) / transferStats.speeds.length).toFixed(2) : 0;
        analyticsDiv.textContent = 'Analytics: ' + transferStats.filesSent + ' files sent, ' +
          (transferStats.totalBytes / 1024 / 1024).toFixed(2) + ' MB, Avg Speed: ' + avgSpeed + ' Mbps';
        localStorage.setItem('transferStats', JSON.stringify(transferStats));
        logDebug('Analytics updated');
      } catch (err) {
        logDebug('Error updating analytics: ' + err.message, err);
      }
    }

    // Log transfer
    function logTransfer(message, isError = false) {
      try {
        const log = document.createElement('div');
        const timestamp = new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });
        log.textContent = '[' + timestamp + '] ' + escapeHTML(message);
        log.className = isError ? 'error' : 'success';
        transferHistory.appendChild(log);
        localStorage.setItem('transferHistory', transferHistory.innerHTML);
        logDebug('Transfer logged: ' + message, isError ? new Error(message) : null);
      } catch (err) {
        logDebug('Error logging transfer: ' + err.message, err);
      }
    }

    // Load transfer history
    function loadTransferHistory() {
      try {
        const savedHistory = localStorage.getItem('transferHistory');
        if (savedHistory) {
          transferHistory.innerHTML = '<h3>Transfer History</h3>' + savedHistory;
        }
        const savedStats = localStorage.getItem('transferStats');
        if (savedStats) {
          transferStats = JSON.parse(savedStats);
          updateAnalytics();
        }
        logDebug('Transfer history loaded');
      } catch (err) {
        logDebug('Error loading transfer history: ' + err.message, err);
        updateStatus('Failed to load transfer history.', true);
      }
    }
    loadTransferHistory();

    // Clear history
    function clearHistory() {
      try {
        transferHistory.innerHTML = '<h3>Transfer History</h3>';
        localStorage.removeItem('transferHistory');
        transferStats = { filesSent: 0, totalBytes: 0, speeds: [] };
        localStorage.removeItem('transferStats');
        updateAnalytics();
        updateStatus('Transfer history cleared.');
        logDebug('History cleared');
      } catch (err) {
        logDebug('Error clearing history: ' + err.message, err);
        updateStatus('Failed to clear history.', true);
      }
    }

    // Update file list
    function updateFileList() {
      try {
        fileList.innerHTML = '';
        selectedFiles.forEach(file => {
          const fileItem = document.createElement('div');
          fileItem.textContent = escapeHTML(file.name) + ' (' + (file.size / 1024 / 1024).toFixed(2) + ' MB, ' + escapeHTML(file.type) + ')';
          fileList.appendChild(fileItem);
        });
        logDebug('File list updated');
      } catch (err) {
        logDebug('Error updating file list: ' + err.message, err);
        updateStatus('Failed to update file list.', true);
      }
    }

    // Update preview table
    function updatePreviewTable() {
      try {
        previewTableBody.innerHTML = '';
        selectedFiles.forEach(file => {
          const row = document.createElement('tr');
          const previewCell = document.createElement('td');
          const reader = new FileReader();
          reader.onload = () => {
            try {
              if (file.type.startsWith('image/')) {
                const img = document.createElement('img');
                img.src = reader.result;
                img.className = 'file-icon';
                img.alt = 'Preview of ' + escapeHTML(file.name);
                previewCell.appendChild(img);
              } else if (file.type.startsWith('video/')) {
                const video = document.createElement('video');
                video.src = reader.result;
                video.className = 'file-icon';
                video.alt = 'Preview of ' + escapeHTML(file.name);
                previewCell.appendChild(video);
              } else if (file.type.startsWith('audio/')) {
                const audio = document.createElement('audio');
                audio.src = reader.result;
                audio.controls = true;
                audio.className = 'file-icon';
                audio.alt = 'Preview of ' + escapeHTML(file.name);
                previewCell.appendChild(audio);
              } else {
                const iconId = file.type === 'application/zip' ? 'zipIcon' :
                              file.type === 'application/pdf' ? 'pdfIcon' :
                              file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ? 'docIcon' : 'fallbackIcon';
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.className = 'file-icon';
                svg.setAttribute('aria-label', iconId === 'zipIcon' ? 'ZIP file icon' :
                                              iconId === 'pdfIcon' ? 'PDF file icon' :
                                              iconId === 'docIcon' ? 'DOCX file icon' : 'Generic file icon');
                const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                use.setAttribute('href', '#' + iconId);
                svg.appendChild(use);
                previewCell.appendChild(svg);
              }
              logDebug('Preview rendered for ' + file.name);
            } catch (err) {
              logDebug('Error rendering preview for ' + file.name + ': ' + err.message, err);
              updateStatus('Error rendering preview for ' + escapeHTML(file.name) + ': ' + err.message, true);
              const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
              svg.className = 'file-icon';
              svg.setAttribute('aria-label', 'Fallback icon');
              const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
              use.setAttribute('href', '#fallbackIcon');
              svg.appendChild(use);
              previewCell.appendChild(svg);
            }
          };
          reader.onerror = () => {
            logDebug('Error reading file ' + file.name + ' for preview: ' + reader.error.message, reader.error);
            updateStatus('Error reading file ' + escapeHTML(file.name) + ' for preview.', true);
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.className = 'file-icon';
            svg.setAttribute('aria-label', 'Fallback icon');
            const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
            use.setAttribute('href', '#fallbackIcon');
            svg.appendChild(use);
            previewCell.appendChild(svg);
          };
          reader.readAsDataURL(file);

          const nameCell = document.createElement('td');
          nameCell.textContent = escapeHTML(file.name);
          const sizeCell = document.createElement('td');
          sizeCell.textContent = (file.size / 1024 / 1024).toFixed(2);
          const typeCell = document.createElement('td');
          typeCell.textContent = escapeHTML(file.type);

          row.appendChild(previewCell);
          row.appendChild(nameCell);
          row.appendChild(sizeCell);
          row.appendChild(typeCell);
          previewTableBody.appendChild(row);
        });
        logDebug('Preview table updated');
      } catch (err) {
        logDebug('Error updating preview table: ' + err.message, err);
        updateStatus('Failed to update preview table.', true);
      }
    }

    // Handle file selection
    fileInput.addEventListener('change', (event) => {
      try {
        fileInput.classList.add('uploading');
        spinner.style.display = 'block';
        setTimeout(() => {
          selectedFiles = Array.from(event.target.files).filter(file => allowedTypes.includes(file.type));
          fileInput.classList.remove('valid', 'invalid');
          if (selectedFiles.length !== event.target.files.length) {
            fileInput.classList.add('invalid');
            updateStatus('Some files were ignored due to unsupported types.', true);
            logDebug('Invalid file types detected');
          } else {
            fileInput.classList.add('valid');
            logDebug('Valid files selected');
          }
          updateFileList();
          updatePreviewTable();
          fileInput.classList.remove('uploading');
          spinner.style.display = 'none';
        }, 500);
      } catch (err) {
        logDebug('Error handling file selection: ' + err.message, err);
        updateStatus('Error selecting files.', true);
        fileInput.classList.remove('uploading');
        spinner.style.display = 'none';
      }
    });

    // Theme change
    function changeTheme() {
      try {
        const theme = document.getElementById('themeSelect').value;
        document.body.classList.remove('light', 'dark', 'blue');
        document.body.classList.add(theme);
        localStorage.setItem('theme', theme);
        logDebug('Theme changed to ' + theme);
      } catch (err) {
        logDebug('Error changing theme: ' + err.message, err);
        updateStatus('Failed to change theme.', true);
      }
    }
    if (localStorage.getItem('theme')) {
      document.getElementById('themeSelect').value = localStorage.getItem('theme');
      changeTheme();
    }

    // Input validation
    sessionPin.addEventListener('input', () => {
      try {
        if (!sessionPin.checkValidity()) {
          updateStatus('PIN must be 4-6 alphanumeric characters.', true);
          sessionPin.classList.add('invalid');
          sessionPin.classList.remove('valid');
        } else {
          statusDiv.textContent = '';
          sessionPin.classList.add('valid');
          sessionPin.classList.remove('invalid');
        }
        logDebug('Session PIN validated');
      } catch (err) {
        logDebug('Error validating session PIN: ' + err.message, err);
      }
    });
    sizeLimitInput.addEventListener('input', () => {
      try {
        if (!sizeLimitInput.checkValidity()) {
          updateStatus('File size limit must be between 1 and 1000 MB.', true);
          sizeLimitInput.classList.add('invalid');
          sizeLimitInput.classList.remove('valid');
        } else {
          statusDiv.textContent = '';
          sizeLimitInput.classList.add('valid');
          sizeLimitInput.classList.remove('invalid');
        }
        logDebug('Size limit validated');
      } catch (err) {
        logDebug('Error validating size limit: ' + err.message, err);
      }
    });

    // Request notification permission
    if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
      Notification.requestPermission();
    }

    // Compute SHA-256 checksum
    async function computeChecksum(file) {
      try {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const checksum = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        logDebug('Checksum computed for file');
        return checksum;
      } catch (err) {
        logDebug('Error computing checksum: ' + err.message, err);
        updateStatus('Failed to compute checksum.', true);
        return '';
      }
    }

    // WebRTC configuration
    const configuration = {
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    };

    // Compress file data
    async function compressData(data, level) {
      try {
        if (level === 'none') return new Blob([data]);
        const stream = new Blob([data]).stream();
        const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
        const compressed = await new Response(compressedStream).blob();
        logDebug('Data compressed with level ' + level);
        return compressed;
      } catch (err) {
        logDebug('Compression error: ' + err.message, err);
        updateStatus('Compression failed: ' + err.message, true);
        throw err;
      }
    }

    // Decompress file data
    async function decompressData(compressed) {
      try {
        const stream = compressed.stream();
        const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
        const decompressed = await new Response(decompressedStream).blob();
        logDebug('Data decompressed');
        return decompressed;
      } catch (err) {
        logDebug('Decompression error: ' + err.message, err);
        updateStatus('Decompression failed: ' + err.message, true);
        throw err;
      }
    }

    // Encryption key generation
    async function generateKey() {
      try {
        const key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        logDebug('Encryption key generated');
        return key;
      } catch (err) {
        logDebug('Key generation error: ' + err.message, err);
        updateStatus('Key generation failed: ' + err.message, true);
        throw err;
      }
    }

    // Encrypt file data
    async function encryptData(data, key) {
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: iv },
          key,
          data
        );
        logDebug('Data encrypted');
        return { encrypted, iv };
      } catch (err) {
        logDebug('Encryption error: ' + err.message, err);
        updateStatus('Encryption failed: ' + err.message, true);
        throw err;
      }
    }

    // Decrypt file data
    async function decryptData(encrypted, key, iv) {
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          key,
          encrypted
        );
        logDebug('Data decrypted');
        return decrypted;
      } catch (err) {
        logDebug('Decryption error: ' + err.message, err);
        updateStatus('Decryption failed: ' + err.message, true);
        return null;
      }
    }

    // Start WebRTC connection
    async function startConnection() {
      try {
        if (!sessionPin.checkValidity()) {
          updateStatus('Please enter a valid session PIN (4-6 alphanumeric characters).', true);
          return;
        }
        localStorage.setItem('sessionPin', sessionPin.value);

        const peerId = Math.random().toString(36).substring(2, 10);
        peerConnections[peerId] = new RTCPeerConnection(configuration);
        dataChannels[peerId] = peerConnections[peerId].createDataChannel('fileTransfer');
        updateConnectionStatus('Initiating...');

        // Session timeout
        clearTimeout(sessionTimeout);
        sessionTimeout = setTimeout(() => {
          for (const peerId in peerConnections) {
            peerConnections[peerId].close();
          }
          peerConnections = {};
          dataChannels = {};
          updateStatus('Session timed out after 10 minutes.', true);
          updateConnectionStatus('Disconnected');
          logDebug('Session timed out');
        }, 10 * 60 * 1000);

        // Handle data channel events
        dataChannels[peerId].onopen = () => {
          updateStatus('Connection established with peer ' + peerId + '!');
          updateConnectionStatus('Connected (' + Object.keys(peerConnections).length + ' peers)');
          cancelButton.disabled = false;
          if (resumeState[peerId]) {
            dataChannels[peerId].send(JSON.stringify({
              type: 'resumeRequest',
              fileName: resumeState[peerId].fileName,
              offset: resumeState[peerId].receivedSize
            }));
          }
          logDebug('Data channel opened for peer ' + peerId);
        };
        dataChannels[peerId].onclose = () => {
          updateStatus('Connection closed with peer ' + peerId + '.');
          updateConnectionStatus('Connected (' + Object.keys(peerConnections).length + ' peers)');
          cancelButton.disabled = true;
          logDebug('Data channel closed for peer ' + peerId);
        };
        dataChannels[peerId].onerror = () => {
          updateStatus('Error in data channel for peer ' + peerId + '.', true);
          updateConnectionStatus('Error');
          logDebug('Data channel error for peer ' + peerId);
        };

        // Handle ICE candidates
        peerConnections[peerId].onicecandidate = (event) => {
          if (event.candidate) {
            console.log('ICE candidate:', event.candidate);
            logDebug('ICE candidate generated');
            // Send candidate
          }
        };

        // Network verification
        async function verifyNetwork() {
          try {
            const response = await fetch('https://api.ipify.org?format=json');
            const { ip } = await response.json();
            console.log('Local IP:', ip);
            logDebug('Network verified with IP ' + ip);
            // Send IP to server
          } catch (err) {
            logDebug('Network verification error: ' + err.message, err);
            updateStatus('Network verification failed: ' + err.message, true);
          }
        }
        verifyNetwork();

        // Create offer
        try {
          const offer = await peerConnections[peerId].createOffer();
          await peerConnections[peerId].setLocalDescription(offer);
          const qrCodeDiv = document.getElementById('qrCode');
          qrCodeDiv.innerHTML = '';
          new QRCode(qrCodeDiv, {
            text: window.location.origin + '?session=' + sessionId,
            width: 200,
            height: 200
          });
          updateStatus('QR code generated. Scan to connect. PIN: ' + sessionPin.value);
          logDebug('QR code generated for session ' + sessionId);
        } catch (err) {
          logDebug('Offer creation error: ' + err.message, err);
          updateStatus('Error creating offer: ' + err.message, true);
        }

        // Handle incoming data channel
        peerConnections[peerId].ondatachannel = (event) => {
          const receiveChannel = event.channel;
          let receivedChunks = [];
          let totalSize = 0;
          let receivedSize = 0;
          let fileName = '';
          let receivedChecksum = '';

          receiveChannel.onmessage = async (event) => {
            try {
              const data = event.data;
              if (typeof data === 'string') {
                const metadata = JSON.parse(data);
                if (metadata.type === 'fileMetadata') {
                  totalSize = metadata.size;
                  fileName = metadata.name;
                  receivedChecksum = metadata.checksum;
                  receivedChunks = resumeState[peerId]?.fileName === fileName ? resumeState[peerId].chunks : [];
                  receivedSize = resumeState[peerId]?.fileName === fileName ? resumeState[peerId].receivedSize : 0;
                  updateStatus('Receiving file: ' + escapeHTML(fileName));
                  updateChecksumStatus('Verifying checksum for ' + escapeHTML(fileName) + '...');
                  progressBar.value = (receivedSize / totalSize) * 100;
                  progressBar.style.display = 'block';
                  spinner.style.display = 'block';
                  transferStartTime = performance.now();
                  logDebug('Receiving file ' + fileName);
                } else if (metadata.type === 'resumeRequest') {
                  sendFileResume(peerId, metadata.fileName, metadata.offset);
                }
              } else if (data instanceof ArrayBuffer) {
                receivedChunks.push(data);
                receivedSize += data.byteLength;
                resumeState[peerId] = { fileName, receivedSize, chunks: receivedChunks };
                progressBar.value = (receivedSize / totalSize) * 100;
                updateBandwidth(receivedSize, transferStartTime);
                if (receivedSize >= totalSize) {
                  const key = await generateKey();
                  const decrypted = await decryptData(new Blob(receivedChunks), key, new Uint8Array(12));
                  if (decrypted) {
                    try {
                      const decompressed = compressionLevel.value === 'none' ? new Blob([decrypted]) : await decompressData(new Blob([decrypted]));
                      const computedChecksum = await computeChecksum(decompressed);
                      if (computedChecksum === receivedChecksum) {
                        updateChecksumStatus('Checksum verified for ' + escapeHTML(fileName) + '.');
                        const url = URL.createObjectURL(decompressed);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = fileName;
                        a.click();
                        URL.revokeObjectURL(url);
                        updateStatus('File ' + escapeHTML(fileName) + ' received successfully!');
                        transferStats.filesSent++;
                        transferStats.totalBytes += totalSize;
                        updateAnalytics();
                        delete resumeState[peerId];
                        logDebug('File ' + fileName + ' received and verified');
                      } else {
                        updateChecksumStatus('Checksum mismatch for ' + escapeHTML(fileName) + '. File may be corrupted.', true);
                        updateStatus('Checksum mismatch for ' + escapeHTML(fileName) + '.', true);
                        logDebug('Checksum mismatch for ' + fileName);
                      }
                    } catch (err) {
                      logDebug('Decompression error for ' + fileName + ': ' + err.message, err);
                      updateStatus('Failed to decompress ' + escapeHTML(fileName) + ': ' + err.message, true);
                    }
                  }
                  progressBar.style.display = 'none';
                  spinner.style.display = 'none';
                }
              }
            } catch (err) {
              logDebug('Error receiving data for ' + fileName + ': ' + err.message, err);
              updateStatus('Error receiving file ' + escapeHTML(fileName) + ': ' + err.message, true);
              progressBar.style.display = 'none';
              spinner.style.display = 'none';
            }
          };
        };

        // Handle session joining
        if (window.location.search.includes('session=')) {
          const remoteSession = new URLSearchParams(window.location.search).get('session');
          if (remoteSession === sessionId && sessionPin.value === localStorage.getItem('sessionPin')) {
            updateConnectionStatus('Connecting to session...');
            try {
              const answer = await peerConnections[peerId].createAnswer();
              await peerConnections[peerId].setLocalDescription(answer);
              logDebug('Session joined with ID ' + remoteSession);
              // Send answer
            } catch (err) {
              logDebug('Answer creation error: ' + err.message, err);
              updateStatus('Error creating answer: ' + err.message, true);
            }
          } else {
            updateStatus('Invalid session ID or PIN.', true);
            logDebug('Invalid session ID or PIN');
          }
        }
      } catch (err) {
        logDebug('Connection error: ' + err.message, err);
        updateStatus('Failed to start connection: ' + err.message, true);
      }
    }

    // Resume file transfer
    async function sendFileResume(peerId, fileName, offset) {
      try {
        const file = selectedFiles.find(f => f.name === fileName);
        if (!file) {
          updateStatus('File ' + escapeHTML(fileName) + ' not found for resume.', true);
          logDebug('File ' + fileName + ' not found for resume');
          return;
        }
        spinner.style.display = 'block';
        const compressed = await compressData(await file.arrayBuffer(), compressionLevel.value);
        const checksum = await computeChecksum(compressed);
        const compressedArray = await compressed.arrayBuffer();
        const chunkSize = 16384;
        const key = await generateKey();

        async function sendChunk(o) {
          if (transferCancelled || !dataChannels[peerId] || dataChannels[peerId].readyState !== 'open') return;
          const slice = compressedArray.slice(o, o + chunkSize);
          try {
            const { encrypted, iv } = await encryptData(slice, key);
            dataChannels[peerId].send(encrypted);
            offset += chunkSize;
            transferredBytes += slice.byteLength;
            progressBar.value = (offset / compressedArray.byteLength) * 100;
            updateBandwidth(transferredBytes, transferStartTime);
            if (offset < compressedArray.byteLength && !transferCancelled) {
              sendChunk(offset);
            } else {
              updateStatus('File ' + escapeHTML(fileName) + ' resumed and sent successfully!');
              updateChecksumStatus('Checksum sent for ' + escapeHTML(fileName) + ': ' + checksum);
              progressBar.style.display = 'none';
              spinner.style.display = 'none';
              transferStats.filesSent++;
              transferStats.totalBytes += compressed.size;
              updateAnalytics();
              logDebug('File ' + fileName + ' resumed and sent');
            }
          } catch (err) {
            logDebug('Chunk sending error for ' + fileName + ': ' + err.message, err);
            updateStatus('Encryption failed for ' + escapeHTML(fileName) + ': ' + err.message, true);
            spinner.style.display = 'none';
          }
        }

        dataChannels[peerId].send(JSON.stringify({
          type: 'fileMetadata',
          name: fileName,
          size: compressed.size,
          type: file.type,
          checksum: checksum
        }));
        sendChunk(offset);
      } catch (err) {
        logDebug('Resume error for ' + fileName + ': ' + err.message, err);
        updateStatus('Failed to resume file ' + escapeHTML(fileName) + ': ' + err.message, true);
        spinner.style.display = 'none';
      }
    }

    // Reconnect
    function reconnect() {
      try {
        if (!sessionPin.checkValidity()) {
          updateStatus('Please enter a valid session PIN.', true);
          logDebug('Invalid session PIN for reconnect');
          return;
        }
        if (sessionPin.value !== localStorage.getItem('sessionPin')) {
          updateStatus('Invalid PIN.', true);
          logDebug('Invalid PIN for reconnect');
          return;
        }
        for (const peerId in peerConnections) {
          peerConnections[peerId].close();
        }
        peerConnections = {};
        dataChannels = {};
        startConnection();
        updateStatus('Reconnecting...');
        logDebug('Reconnecting');
      } catch (err) {
        logDebug('Reconnect error: ' + err.message, err);
        updateStatus('Failed to reconnect: ' + err.message, true);
      }
    }

    // Cancel transfer
    function cancelTransfer() {
      try {
        transferCancelled = true;
        for (const peerId in dataChannels) {
          dataChannels[peerId].close();
        }
        updateStatus('Transfer cancelled.', true);
        progressBar.style.display = 'none';
        spinner.style.display = 'none';
        cancelButton.disabled = true;
        logDebug('Transfer cancelled');
      } catch (err) {
        logDebug('Cancel transfer error: ' + err.message, err);
        updateStatus('Failed to cancel transfer: ' + err.message, true);
      }
    }

    // Send files
    async function sendFile() {
      try {
        if (Object.keys(dataChannels).length === 0 || !Object.values(dataChannels).some(dc => dc.readyState === 'open')) {
          updateStatus('No active connections.', true);
          logDebug('No active connections');
          return;
        }
        if (selectedFiles.length === 0) {
          updateStatus('No file selected.', true);
          logDebug('No files selected');
          return;
        }
        if (!sizeLimitInput.checkValidity()) {
          updateStatus('Invalid file size limit.', true);
          logDebug('Invalid file size limit');
          return;
        }

        spinner.style.display = 'block';
        const maxSize = parseInt(sizeLimitInput.value) * 1024 * 1024;
        transferCancelled = false;
        transferStartTime = performance.now();
        transferredBytes = 0;
        const key = await generateKey();
        for (const file of selectedFiles) {
          if (transferCancelled) break;
          if (!allowedTypes.includes(file.type)) {
            updateStatus('File ' + escapeHTML(file.name) + ' has unsupported type: ' + file.type + '.', true);
            logDebug('Unsupported file type: ' + file.type);
            continue;
          }
          if (file.size > maxSize) {
            updateStatus('File ' + escapeHTML(file.name) + ' exceeds size limit (' + sizeLimitInput.value + ' MB).', true);
            logDebug('File ' + file.name + ' exceeds size limit');
            continue;
          }

          const reader = new FileReader();
          reader.onload = async () => {
            try {
              const compressed = await compressData(reader.result, compressionLevel.value);
              const checksum = await computeChecksum(compressed);
              for (const peerId in dataChannels) {
                if (dataChannels[peerId].readyState === 'open') {
                  dataChannels[peerId].send(JSON.stringify({
                    type: 'fileMetadata',
                    name: file.name,
                    size: compressed.size,
                    type: file.type,
                    checksum: checksum
                  }));
                }
              }

              const chunkSize = 16384;
              let offset = resumeState[peerId]?.fileName === file.name ? resumeState[peerId].offset : 0;
              const compressedArray = await compressed.arrayBuffer();

              async function sendChunk(o) {
                if (transferCancelled) return;
                const slice = compressedArray.slice(o, o + chunkSize);
                try {
                  const { encrypted, iv } = await encryptData(slice, key);
                  for (const peerId in dataChannels) {
                    if (dataChannels[peerId].readyState === 'open') {
                      dataChannels[peerId].send(encrypted);
                    }
                  }
                  offset += chunkSize;
                  resumeState[peerId] = { fileName: file.name, offset };
                  transferredBytes += slice.byteLength;
                  progressBar.value = (offset / compressedArray.byteLength) * 100;
                  updateBandwidth(transferredBytes, transferStartTime);
                  if (offset < compressedArray.byteLength && !transferCancelled) {
                    sendChunk(offset);
                  } else {
                    updateStatus('File ' + escapeHTML(file.name) + ' sent successfully!');
                    updateChecksumStatus('Checksum sent for ' + escapeHTML(file.name) + ': ' + checksum);
                    progressBar.style.display = 'none';
                    spinner.style.display = 'none';
                    transferStats.filesSent++;
                    transferStats.totalBytes += compressed.size;
                    updateAnalytics();
                    delete resumeState[peerId];
                    logDebug('File ' + file.name + ' sent successfully');
                  }
                } catch (err) {
                  logDebug('Chunk sending error for ' + file.name + ': ' + err.message, err);
                  updateStatus('Encryption failed for ' + escapeHTML(file.name) + ': ' + err.message, true);
                  spinner.style.display = 'none';
                }
              }

              sendChunk(offset);
            } catch (err) {
              logDebug('Compression error for ' + file.name + ': ' + err.message, err);
              updateStatus('Compression failed for ' + escapeHTML(file.name) + ': ' + err.message, true);
              spinner.style.display = 'none';
            }
          };

          reader.onerror = () => {
            logDebug('File read error for ' + file.name + ': ' + reader.error.message, reader.error);
            updateStatus('Error reading file ' + escapeHTML(file.name) + '.', true);
            spinner.style.display = 'none';
          };
          reader.readAsArrayBuffer(file);
          progressBar.style.display = 'block';
        }
      } catch (err) {
        logDebug('Send file error: ' + err.message, err);
        updateStatus('Failed to send file: ' + err.message, true);
        spinner.style.display = 'none';
      }
    }

    // Drag-and-drop support
    const container = document.querySelector('.container');
    container.addEventListener('dragover', (e) => {
      e.preventDefault();
      container.style.backgroundColor = document.body.classList.contains('dark') ? '#555' : 
        document.body.classList.contains('blue') ? '#b3d4fc' : '#e0e0e0';
    });
    container.addEventListener('dragleave', () => {
      container.style.backgroundColor = document.body.classList.contains('dark') ? '#444' : 
        document.body.classList.contains('blue') ? '#f0f8ff' : 'white';
    });
    container.addEventListener('drop', (e) => {
      try {
        e.preventDefault();
        container.style.backgroundColor = document.body.classList.contains('dark') ? '#444' : 
          document.body.classList.contains('blue') ? '#f0f8ff' : 'white';
        fileInput.classList.add('uploading');
        spinner.style.display = 'block';
        setTimeout(() => {
          selectedFiles = Array.from(e.dataTransfer.files).filter(file => allowedTypes.includes(file.type));
          fileInput.files = e.dataTransfer.files;
          fileInput.classList.remove('valid', 'invalid');
          if (selectedFiles.length !== e.dataTransfer.files.length) {
            fileInput.classList.add('invalid');
            updateStatus('Some files were ignored due to invalid file types.', true);
            logDebug('Invalid file types detected in drag-and-drop');
          } else {
            fileInput.classList.add('valid');
            logDebug('Valid files selected via drag-and-drop');
          }
          updateFileList();
          updatePreviewTable();
          fileInput.classList.remove('uploading');
          spinner.style.display = 'none';
        }, 500);
      } catch (err) {
        logDebug('Drag-and-drop error: ' + err.message, error);
        updateStatus('Failed to process dropped files: ' + err.message, true);
        fileInput.classList.remove('uploading');
        spinner.style.display = 'none';
      }
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      try {
        if (e.key === 'Enter' && document.activeElement.tagName === 'BUTTON') {
          document.activeElement.click();
          logDebug('Button activated via Enter key');
        }
      } catch (err) {
        logDebug('Keyboard navigation error: ' + err.message, err);
        updateStatus('Error handling keyboard input: ' + err.message, true);
      }
    });
