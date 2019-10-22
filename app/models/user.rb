class User < ApplicationRecord
	has_many :courses
	before_action :authenticate_user!
	before_action :user_signed_in?
	current_user
	user_session

	def new
	end 

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end
