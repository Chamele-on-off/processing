from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.requisites import Requisite
from utils.decorators import trader_required

bp = Blueprint('requisites', __name__, url_prefix='/requisites')

@bp.route('/', methods=['GET'])
@jwt_required()
@trader_required
def get_requisites():
    user_id = get_jwt_identity()['id']
    requisites = Requisite.get_active_for_trader(user_id)
    return jsonify({
        'success': True,
        'data': [Requisite.to_dict(r) for r in requisites]
    })

@bp.route('/', methods=['POST'])
@jwt_required()
@trader_required
def create_requisite():
    user_id = get_jwt_identity()['id']
    data = request.get_json()
    
    requisite = Requisite.create(
        user_id=user_id,
        type=data['type'],
        details=data['details'],
        max_amount=data.get('max_amount'),
        min_amount=data.get('min_amount', 0),
        currency=data.get('currency', 'RUB')
    )
    
    return jsonify({
        'success': True,
        'data': Requisite.to_dict(requisite)
    }), 201

@bp.route('/<int:req_id>', methods=['DELETE'])
@jwt_required()
@trader_required
def delete_requisite(req_id):
    user_id = get_jwt_identity()['id']
    Requisite.deactivate(req_id, user_id)
    return jsonify({'success': True})