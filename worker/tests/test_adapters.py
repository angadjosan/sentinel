"""Tests for framework adapters."""
from __future__ import annotations

import pytest

from sentinel_worker.adapters.django import DjangoAdapter
from sentinel_worker.adapters.express import ExpressAdapter
from sentinel_worker.adapters.fastapi import FastAPIAdapter
from sentinel_worker.adapters.nextjs import NextJSAdapter
from sentinel_worker.adapters.rails import RailsAdapter
from sentinel_worker.adapters.spring import SpringAdapter
from sentinel_worker.adapters.base import NodeRecord, EdgeRecord


# ---------------------------------------------------------------------------
# ExpressAdapter
# ---------------------------------------------------------------------------

EXPRESS_CONTENT_WITH_AUTH = """\
const express = require('express');
const app = express();

app.use(authMiddleware);
app.get('/users', getUsers);
app.post('/users', createUser);
"""

EXPRESS_CONTENT_NO_AUTH = """\
const express = require('express');
const app = express();

app.get('/public', publicHandler);
"""

EXPRESS_CONTENT_AUTH_AFTER = """\
const express = require('express');
const app = express();

app.get('/public', publicHandler);
app.use(authMiddleware);
app.get('/private', privateHandler);
"""

EXPRESS_NON_EXPRESS = """\
import flask
from flask import Flask
app = Flask(__name__)

@app.route('/hello')
def hello():
    return 'Hello'
"""


class TestExpressAdapter:
    adapter = ExpressAdapter()

    def test_detect_true_for_express_content(self):
        assert self.adapter.detect("routes.js", EXPRESS_CONTENT_WITH_AUTH) is True

    def test_detect_true_router(self):
        content = "const router = express.Router(); router.get('/items', handler);"
        assert self.adapter.detect("router.js", content) is True

    def test_detect_false_for_non_express(self):
        assert self.adapter.detect("app.py", EXPRESS_NON_EXPRESS) is False

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("routes.js", EXPRESS_CONTENT_WITH_AUTH, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_nodes_present(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 1

    def test_extract_auth_required_when_auth_middleware_before_route(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.auth_required for n in route_nodes)

    def test_extract_no_auth_when_no_middleware(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_NO_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) == 1
        assert route_nodes[0].auth_required is False

    def test_extract_auth_only_after_middleware_registration(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_AUTH_AFTER, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        # /public should come before authMiddleware → no auth
        public_routes = [n for n in route_nodes if "public" in n.name]
        private_routes = [n for n in route_nodes if "private" in n.name]
        assert len(public_routes) == 1
        assert public_routes[0].auth_required is False
        assert len(private_routes) == 1
        assert private_routes[0].auth_required is True

    def test_extract_guarded_by_edges_have_order_index(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_WITH_AUTH, {})
        guarded_by = [e for e in edges if e.kind == "GUARDED_BY"]
        assert len(guarded_by) >= 1
        for edge in guarded_by:
            assert edge.order_index is not None

    def test_extract_route_is_entry_point(self):
        nodes, edges = self.adapter.extract("routes.js", EXPRESS_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.is_entry_point for n in route_nodes)

    def test_extract_empty_content(self):
        nodes, edges = self.adapter.extract("routes.js", "const x = 1;", {})
        assert nodes == [] or all(n.kind != "ROUTE" for n in nodes)


# ---------------------------------------------------------------------------
# FastAPIAdapter
# ---------------------------------------------------------------------------

FASTAPI_CONTENT_WITH_AUTH = """\
from fastapi import FastAPI, Depends
from .auth import get_current_user

app = FastAPI()

@app.get('/users')
async def get_users(current_user=Depends(get_current_user)):
    return []

@app.post('/items')
async def create_item(current_user=Depends(get_current_user)):
    return {}
"""

FASTAPI_CONTENT_NO_AUTH = """\
from fastapi import FastAPI

app = FastAPI()

@app.get('/public')
async def public_endpoint():
    return {'status': 'ok'}
"""

FASTAPI_NON = """\
import flask
@app.route('/hello')
def hello():
    return 'hi'
"""


class TestFastAPIAdapter:
    adapter = FastAPIAdapter()

    def test_detect_true_for_fastapi_content(self):
        assert self.adapter.detect("main.py", FASTAPI_CONTENT_WITH_AUTH) is True

    def test_detect_true_router(self):
        content = "@router.post('/items')\nasync def create():\n    pass"
        assert self.adapter.detect("router.py", content) is True

    def test_detect_false_for_flask(self):
        assert self.adapter.detect("app.py", FASTAPI_NON) is False

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("main.py", FASTAPI_CONTENT_WITH_AUTH, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_nodes(self):
        nodes, edges = self.adapter.extract("main.py", FASTAPI_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 2

    def test_extract_auth_required_with_depends(self):
        nodes, edges = self.adapter.extract("main.py", FASTAPI_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.auth_required for n in route_nodes)

    def test_extract_no_auth_without_depends(self):
        nodes, edges = self.adapter.extract("main.py", FASTAPI_CONTENT_NO_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) == 1
        assert route_nodes[0].auth_required is False

    def test_extract_route_is_entry_point(self):
        nodes, edges = self.adapter.extract("main.py", FASTAPI_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.is_entry_point for n in route_nodes)


# ---------------------------------------------------------------------------
# DjangoAdapter
# ---------------------------------------------------------------------------

DJANGO_URLS_CONTENT = """\
from django.urls import path
from . import views

urlpatterns = [
    path('users/', views.user_list),
    path('admin/', views.admin_panel),
]
"""

DJANGO_WITH_AUTH = """\
from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    path('dashboard/', login_required(views.dashboard)),
]
"""

DJANGO_NON = """\
from flask import Flask
app = Flask(__name__)
"""


class TestDjangoAdapter:
    adapter = DjangoAdapter()

    def test_detect_true_for_urls_py(self):
        assert self.adapter.detect("urls.py", DJANGO_URLS_CONTENT) is True

    def test_detect_true_for_path_pattern(self):
        assert self.adapter.detect("other.py", DJANGO_URLS_CONTENT) is True

    def test_detect_false_for_flask(self):
        assert self.adapter.detect("app.py", DJANGO_NON) is False

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("urls.py", DJANGO_URLS_CONTENT, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_nodes(self):
        nodes, edges = self.adapter.extract("urls.py", DJANGO_URLS_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 2

    def test_extract_parses_path_correctly(self):
        nodes, edges = self.adapter.extract("urls.py", DJANGO_URLS_CONTENT, {})
        route_names = [n.name for n in nodes if n.kind == "ROUTE"]
        assert any("users" in name for name in route_names)

    def test_extract_no_auth_by_default(self):
        nodes, edges = self.adapter.extract("urls.py", DJANGO_URLS_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(not n.auth_required for n in route_nodes)

    def test_extract_route_is_entry_point(self):
        nodes, edges = self.adapter.extract("urls.py", DJANGO_URLS_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.is_entry_point for n in route_nodes)


# ---------------------------------------------------------------------------
# NextJSAdapter
# ---------------------------------------------------------------------------

NEXTJS_ROUTE_CONTENT = """\
import { getServerSession } from 'next-auth';

export async function GET(request) {
    const session = await getServerSession();
    if (!session) return new Response('Unauthorized', { status: 401 });
    return Response.json({ data: [] });
}
"""

NEXTJS_ROUTE_NO_AUTH = """\
export async function GET(request) {
    return Response.json({ data: [] });
}
"""


class TestNextJSAdapter:
    adapter = NextJSAdapter()

    def test_detect_true_for_app_route(self):
        assert self.adapter.detect("app/api/users/route.ts", NEXTJS_ROUTE_CONTENT) is True

    def test_detect_true_for_pages_api(self):
        assert self.adapter.detect("pages/api/users.ts", NEXTJS_ROUTE_NO_AUTH) is True

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("app/api/users/route.ts", NEXTJS_ROUTE_CONTENT, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_auth_required_with_get_server_session(self):
        nodes, edges = self.adapter.extract("app/api/users/route.ts", NEXTJS_ROUTE_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 1
        assert all(n.auth_required for n in route_nodes)

    def test_extract_route_no_auth_without_patterns(self):
        nodes, edges = self.adapter.extract("app/api/public/route.ts", NEXTJS_ROUTE_NO_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 1
        assert all(not n.auth_required for n in route_nodes)

    def test_extract_middleware_file(self):
        content = "import { withAuth } from 'next-auth/middleware';\nexport default withAuth;"
        nodes, edges = self.adapter.extract("middleware.ts", content, {})
        mw_nodes = [n for n in nodes if n.kind == "MIDDLEWARE"]
        assert len(mw_nodes) >= 1


# ---------------------------------------------------------------------------
# RailsAdapter
# ---------------------------------------------------------------------------

RAILS_ROUTES_CONTENT = """\
Rails.application.routes.draw do
  get '/users', to: 'users#index'
  post '/users', to: 'users#create'
  get '/admin', to: 'admin#index'
end
"""

RAILS_CONTROLLER_WITH_AUTH = """\
class UsersController < ApplicationController
  before_action :authenticate_user!

  def index
    @users = User.all
  end
end
"""

RAILS_NON = """\
from flask import Flask
app = Flask(__name__)
"""


class TestRailsAdapter:
    adapter = RailsAdapter()

    def test_detect_true_for_routes_rb(self):
        assert self.adapter.detect("config/routes.rb", RAILS_ROUTES_CONTENT) is True

    def test_detect_true_for_routes_draw(self):
        assert self.adapter.detect("routes.rb", RAILS_ROUTES_CONTENT) is True

    def test_detect_false_for_flask(self):
        assert self.adapter.detect("app.py", RAILS_NON) is False

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("config/routes.rb", RAILS_ROUTES_CONTENT, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_nodes(self):
        nodes, edges = self.adapter.extract("config/routes.rb", RAILS_ROUTES_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 2

    def test_extract_auth_required_with_before_action(self):
        nodes, edges = self.adapter.extract("controllers/users_controller.rb", RAILS_CONTROLLER_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.auth_required for n in route_nodes)

    def test_extract_no_auth_without_before_action(self):
        nodes, edges = self.adapter.extract("config/routes.rb", RAILS_ROUTES_CONTENT, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(not n.auth_required for n in route_nodes)


# ---------------------------------------------------------------------------
# SpringAdapter
# ---------------------------------------------------------------------------

SPRING_CONTENT_WITH_AUTH = """\
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
public class UserController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
}
"""

SPRING_CONTENT_NO_AUTH = """\
import org.springframework.web.bind.annotation.*;

@RestController
public class PublicController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "OK";
    }
}
"""

SPRING_NON = """\
from flask import Flask
app = Flask(__name__)
"""


class TestSpringAdapter:
    adapter = SpringAdapter()

    def test_detect_true_for_spring_content(self):
        assert self.adapter.detect("UserController.java", SPRING_CONTENT_WITH_AUTH) is True

    def test_detect_false_for_flask(self):
        assert self.adapter.detect("app.py", SPRING_NON) is False

    def test_extract_returns_tuple(self):
        result = self.adapter.extract("UserController.java", SPRING_CONTENT_WITH_AUTH, {})
        assert isinstance(result, tuple) and len(result) == 2

    def test_extract_route_nodes(self):
        nodes, edges = self.adapter.extract("UserController.java", SPRING_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 1

    def test_extract_auth_required_with_pre_authorize(self):
        nodes, edges = self.adapter.extract("UserController.java", SPRING_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        # The /users GET has @PreAuthorize just above it
        users_routes = [n for n in route_nodes if "users" in n.name.lower()]
        assert len(users_routes) >= 1
        assert users_routes[0].auth_required is True

    def test_extract_no_auth_without_annotation(self):
        nodes, edges = self.adapter.extract("PublicController.java", SPRING_CONTENT_NO_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert len(route_nodes) >= 1
        assert all(not n.auth_required for n in route_nodes)

    def test_extract_route_is_entry_point(self):
        nodes, edges = self.adapter.extract("UserController.java", SPRING_CONTENT_WITH_AUTH, {})
        route_nodes = [n for n in nodes if n.kind == "ROUTE"]
        assert all(n.is_entry_point for n in route_nodes)


# ---------------------------------------------------------------------------
# Common contract: all adapters return (list, list)
# ---------------------------------------------------------------------------

ALL_ADAPTERS = [
    (ExpressAdapter(), "routes.js", EXPRESS_CONTENT_WITH_AUTH),
    (FastAPIAdapter(), "main.py", FASTAPI_CONTENT_WITH_AUTH),
    (NextJSAdapter(), "app/api/users/route.ts", NEXTJS_ROUTE_CONTENT),
    (DjangoAdapter(), "urls.py", DJANGO_URLS_CONTENT),
    (RailsAdapter(), "config/routes.rb", RAILS_ROUTES_CONTENT),
    (SpringAdapter(), "UserController.java", SPRING_CONTENT_WITH_AUTH),
]


@pytest.mark.parametrize("adapter,file_path,content", ALL_ADAPTERS)
def test_all_adapters_return_tuple_of_lists(adapter, file_path, content):
    result = adapter.extract(file_path, content, {})
    assert isinstance(result, tuple)
    nodes, edges = result
    assert isinstance(nodes, list)
    assert isinstance(edges, list)


@pytest.mark.parametrize("adapter,file_path,content", ALL_ADAPTERS)
def test_all_adapters_no_exception_on_valid_input(adapter, file_path, content):
    # Should not raise
    nodes, edges = adapter.extract(file_path, content, {})
    for node in nodes:
        assert isinstance(node, NodeRecord)
    for edge in edges:
        assert isinstance(edge, EdgeRecord)


@pytest.mark.parametrize("adapter,file_path,content", ALL_ADAPTERS)
def test_all_adapters_node_ids_are_strings(adapter, file_path, content):
    nodes, edges = adapter.extract(file_path, content, {})
    for node in nodes:
        assert isinstance(node.id, str) and len(node.id) > 0


@pytest.mark.parametrize("adapter,file_path,content", ALL_ADAPTERS)
def test_all_adapters_detect_returns_true_for_matching_content(adapter, file_path, content):
    assert adapter.detect(file_path, content) is True
