# Copyright (c) 2024 Plataformatec
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule MyApp.Server do
  use GenServer
  require Logger
  alias MyApp.Config
  import MyApp.Utils, only: [format_timestamp: 1]

  @moduledoc """
  A GenServer that manages TCP connections and handles
  incoming requests from clients.
  """

  @default_port 4000
  @max_connections 100
  @timeout 30_000

  defstruct [:socket, :port, :connections, :started_at]

  def start_link(opts \\ []) do
    port = Keyword.get(opts, :port, @default_port)
    GenServer.start_link(__MODULE__, port, name: __MODULE__)
  end

  @impl true
  def init(port) do
    Logger.info("Starting server on port #{port}")

    case :gen_tcp.listen(port, [:binary, active: false, reuseaddr: true]) do
      {:ok, socket} ->
        state = %__MODULE__{
          socket: socket,
          port: port,
          connections: %{},
          started_at: DateTime.utc_now()
        }

        {:ok, state, {:continue, :accept}}

      {:error, reason} ->
        Logger.error("Failed to listen on port #{port}: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:accept, state) do
    case :gen_tcp.accept(state.socket, @timeout) do
      {:ok, client} ->
        Logger.debug("New connection accepted")
        {:ok, pid} = Task.start(fn -> handle_client(client) end)
        :gen_tcp.controlling_process(client, pid)

        connections = Map.put(state.connections, pid, client)
        {:noreply, %{state | connections: connections}, {:continue, :accept}}

      {:error, :timeout} ->
        {:noreply, state, {:continue, :accept}}

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        {:stop, reason, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    connections = Map.delete(state.connections, pid)
    {:noreply, %{state | connections: connections}}
  end

  defp handle_client(socket) do
    case :gen_tcp.recv(socket, 0) do
      {:ok, data} ->
        response = process_request(data)
        :gen_tcp.send(socket, response)
        handle_client(socket)

      {:error, :closed} ->
        Logger.debug("Client disconnected")
        :ok
    end
  end

  defp process_request(data) do
    "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(data)}\r\n\r\n#{data}"
  end
end