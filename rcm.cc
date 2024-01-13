#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <memory>
#include <cassert>
#include <thread>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>
#include <set>
#include <iostream>
using namespace std;

int listenTCP(uint16_t port)
{
  int sockfd;  // listen on sock_fd
  struct addrinfo hints, *servinfo, *p;
  //struct sockaddr_storage their_addr; // connector's address information
  //socklen_t sin_size;
  int yes=1;
  //char s[INET6_ADDRSTRLEN];
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  string port_str = to_string(port);
  if ((rv = getaddrinfo(NULL, port_str.c_str(), &hints, &servinfo)) != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("socket() syscall");
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
      perror("setsockopt SO_REUSEADDR");
      exit(1);
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sockfd);
      perror("bind() syscall");
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo); // all done with this structure

  if (p == NULL)
  {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }
  if (listen(sockfd, 10) == -1) // allow connection backlog of up to 10
  {
    perror("listen() syscall");
    exit(1);
  }
  printf("successfully bound to %d\n", port);
  return sockfd;
}

// Basically like VAR=`cmd` in bash.
string runShellSync(const char* cmd)
{
  char buffer[1024];
  string ret;
  unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  assert(pipe);

  while (fgets(buffer, 1024, pipe.get()) != nullptr)
    ret += buffer;
  return ret;
}

vector<string> splitString(string s, char delim)
{
  vector<string> result;
  stringstream ss(s);
  string item;
  while (getline(ss, item, delim))
    result.push_back(item);
  return result;
}



// hack to filter chrome's duplicate requests
mutex g_mutex;
uint64_t g_next_nonce = 1;
uint64_t g_last_change_msse = 0;
set<uint64_t> g_nonces_used;


string buildPage()
{
  string title, artist, filename;

  string mpc_blob = runShellSync("mpc --format=\"%title%\\n%artist%\\n%file%\"");
  auto info = splitString(mpc_blob, '\n');
  string player_status;
  if (auto vol_ind = mpc_blob.find("volume:"); vol_ind != string::npos)
    player_status = mpc_blob.substr(vol_ind);
  if (info.size() > 0)
    title = info[0];
  if (info.size() > 1)
    artist = info[1];
  if (info.size() > 2)
    filename = info[2];
  string display = title.empty() ? filename : (title + " by " + artist);

  string cur_nonce;
  {
    const lock_guard<mutex> lock(g_mutex);
    cur_nonce = std::to_string(g_next_nonce);
    g_next_nonce++;
  }
  string page = "HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\n\r\n";
  page +=
"<head><meta charset=\"utf-8\"/><style>\nh1 {\n"
"  font-size: 6em;\n"
"}\n</style></head><body>\n"
"Now playing:<br><b>"+display+"</b><br><br>"+player_status+"<br>\n"
"<h1>\n"
"  <a href=\"RCMLAZYSTARTvoldnRCixMlz"+cur_nonce+"zlMxiCR\">. -- .</a> VOL <a href=\"RCMLAZYSTARTvolupRCixMlz"+cur_nonce+"zlMxiCR\">. + .</a>\n"
"</h1><br>\n"
"<h1>\n"
"  <a href=\"RCMLAZYSTARTprevRCixMlz"+cur_nonce+"zlMxiCR\">. &#x23EE .</a> . . <a href=\"RCMLAZYSTARTplpauseRCixMlz"+cur_nonce+"zlMxiCR\">. &#x23EF .</a> . . <a href=\"RCMLAZYSTARTnextRCixMlz"+cur_nonce+"zlMxiCR\">. &#x23ED .</a>\n"
"</h1><br>\n"
"<font size=\"+2\"><ul>\n";


  vector<string> playlists = splitString(runShellSync("mpc lsplaylists | sort"), '\n');
  for (const string& playlist : playlists)
  {
    page += "<li><a href=\"RCMLAZYSTARTplaylist/"+playlist+
            "RCixMlz"+cur_nonce+"zlMxiCR\">"+playlist+"</a></li>\n";
  }
  page += "</ul></font></body>\n";
  return page;
}

constexpr char kRedirect[] =
"HTTP/1.1 302 Found\r\n"
"Location: /RCMLAZYSTARTmainRCixMlz1zlMxiCR\r\n\r\n";
constexpr int kRedirectLen = strlen(kRedirect);

enum class Reaction { Nothing, Redirect, Display };
Reaction handleCommand(string cmd, uint64_t cmd_nonce)
{
  cout << "handling command: " << cmd << endl;
  if (cmd == "main")
    return Reaction::Display;

  if (cmd == "prev" || cmd == "plpause" || cmd == "next" || cmd == "voldn" ||
      cmd == "volup" || cmd.find("playlist/") == 0)
  {
    const lock_guard<mutex> lock(g_mutex);
    auto result = g_nonces_used.insert(cmd_nonce);
    if (!result.second)
    {
      cout<<"rejecting "<<cmd<<" with nonce "<<cmd_nonce<<" as a duplicate"<<endl;
      return Reaction::Redirect;
    }
    g_last_change_msse = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  if (cmd == "prev")
    runShellSync("mpc prev");
  else if (cmd == "plpause")
    runShellSync("mpc toggle");
  else if (cmd == "next")
    runShellSync("mpc next");
  else if (cmd == "voldn")
    runShellSync("mpc volume -10");
  else if (cmd == "volup")
    runShellSync("mpc volume +10");
  else if (cmd.find("playlist/") == 0)
  {
    std::string playlist = cmd.substr(9);
    if (playlist.find_first_not_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        == string::npos)
    {
      cout << "loading playlist: " << playlist << endl;
      std::string runcmd = "mpc stop ; mpc clear ; mpc load ";
      runcmd += playlist + " ; mpc play";
      runShellSync(runcmd.c_str());
    }
  }
  else
    return Reaction::Nothing;
  return Reaction::Redirect;
}

void httpSession(int fd)
{
  assert(fd != -1);
  char buf[1024];
  int n = recv(fd, buf, 1023, 0);
  if (n < 0)
    perror("recv()");
  else
  {
    buf[n] = 0;
    const char* start = strstr(buf, "RCMLAZYSTART");
    const char* end = strstr(buf, "RCixMlz");
    const char* end2 = strstr(buf, "zlMxiCR");
    if (start != 0 && end != 0 && end2 != 0)
    {
      uint64_t nonce = 0;
      try { nonce = std::stoi(string(end+7, end2 - (end+7))); }
      catch (const std::exception& e) {}
      switch (handleCommand(string(start+12, (end) - (start+12)), nonce))
      {
        case Reaction::Nothing:
        break;
        case Reaction::Redirect:
          send(fd, kRedirect, kRedirectLen, 0);
        break;
        case Reaction::Display:
          string reply = buildPage();
          send(fd, reply.c_str(), reply.length(), 0);
        break;
      }
    }
  }
  shutdown(fd, SHUT_RDWR);
  close(fd);
}

int main()
{
  std::thread resetter([]()
  {
    while (true)
    {
      std::this_thread::sleep_for(std::chrono::hours(1));

      const lock_guard<mutex> lock(g_mutex);
      uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
      if (g_last_change_msse < now - 1000 * 60 * 59)
        g_nonces_used.clear();
    }
  });
  resetter.detach();

  int listen_fd = listenTCP(10005);
  while (true)
  {
    int fd = accept(listen_fd, nullptr, nullptr);
    thread t(httpSession, fd);
    t.detach();
  }

  close(listen_fd);
}
